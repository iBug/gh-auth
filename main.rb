#!/usr/bin/ruby
# frozen_string_literal: true

require 'base64'
require 'cgi'
require 'erb'
require 'json'
require 'net/http'
require 'openssl'
require 'rexml/document'
require 'rexml/xpath'
require 'securerandom'
require 'time'
require 'yaml'

TEMPLATE_DIR = 'templates'
CONFIG = YAML.load(ERB.new(File.read('config.yml')).result)

def hmac_signature(key, data)
  digest = OpenSSL::Digest.new('sha1')
  OpenSSL::HMAC.hexdigest(digest, key, data)
end

class Template
  def initialize(name = 'base')
    @template = self.class.get(name)
  end

  def render
    @template.result(binding)
  end

  class << self
    def get(name)
      ERB.new(File.read(File.join(TEMPLATE_DIR, "#{name}.erb")))
    end

    def base
      @base ||= new
    end
  end
end

class RequestHandler
  def initialize(event)
    @event = event
    @context = event['requestContext']

    @req_method = @context['http']['method'].upcase
    @req_host = @context['domainName']
    @req_path = @event['rawPath']
    @req_params = @event['queryStringParameters'] || {}
    @req_headers = @event['headers']
    @req_body = @event['body']
    @req_body = Base64.decode64(@req_body) if @event['isBase64Encoded']

    @res_body = ''
    @res_code = 200
    @res_headers = { 'Content-Type' => 'text/plain' }
    @res_cookies = []
  end

  def h(s)
    CGI.escapeHTML s
  end

  def render(template)
    @res_body = Template.base.render do
      Template.get(template).result(binding)
    end
    @res_headers['Content-Type'] = 'text/html'
  end

  def redirect(target, code = 302)
    @res_code = code
    @res_headers['Location'] = target
  end

  def cookies
    @cookies ||= (@event['cookies'] || []).map do |cookie|
      c = CGI::Cookie.parse(cookie.split(';', 2)[0]).first
      [c[0], c[1][0]]
    end.to_h
  end

  def state
    @state ||= begin
      return cookies['state'] if cookies&.key? 'state'

      s = SecureRandom.hex(16)
      set_cookie 'state', s, Time.now + CONFIG['session_expiry']
      s
    end
  end

  def set_cookie(name, value = nil, expires = nil)
    expires ||= Time.now + CONFIG['session_expiry']
    if value.nil?
      value = ''
      expires = Time.at 0
    end
    @res_cookies << CGI::Cookie.new('name' => name, 'value' => value, 'path' => '/', 'expires' => expires).to_s
  end

  def id_from_cookie(cookie_name)
    return unless cookies&.key? cookie_name

    id, timestamp, sig = cookies[cookie_name].split(':')
    hmac = hmac_signature(CONFIG['session_key'], "#{id}:#{timestamp}")
    raise unless hmac == sig
    raise unless Time.now.to_i < timestamp.to_i + CONFIG['session_expiry']

    id
  rescue StandardError => e
    warn ([e.message] + e.backtrace).join $/
    set_cookie cookie_name
    nil
  end

  def id_to_cookie(cookie_name, id)
    now = Time.now
    payload = "#{id}:#{now.to_i}"
    sig = hmac_signature(CONFIG['session_key'], payload)
    set_cookie cookie_name, "#{payload}:#{sig}", now + CONFIG['session_expiry']
    sig
  end

  def user_ustc
    @user_ustc ||= id_from_cookie 'user_ustc'
  end

  def user_github
    @user_github ||= id_from_cookie 'user_github'
  end

  def auth_ustc
    jump = "#{CONFIG['cas']['redirect_uri']}?#{URI.encode_www_form({ cas_id: state })}"
    service = "#{CONFIG['cas']['redirector']}?#{URI.encode_www_form({ jump: jump })}"
    ticket = @req_params['ticket']
    return redirect "#{CONFIG['cas']['url']}?#{URI.encode_www_form({ service: service })}" unless ticket

    raise unless @req_params['cas_id'] == state

    res = Net::HTTP.get_response(URI("#{CONFIG['cas']['validate']}?#{URI.encode_www_form({ "service": service, "ticket": ticket })}"))
    raise unless res.is_a? Net::HTTPSuccess

    xml = REXML::Document.new res.body
    raise unless xml.root.namespaces['cas'] == 'http://www.yale.edu/tp/cas'
    raise unless xml.root.elements[1].name == 'authenticationSuccess'

    @user_ustc = REXML::XPath.match(xml, '//cas:serviceResponse/cas:authenticationSuccess/cas:user').first.text
    warn "Authenticated with USTC user #{@user_ustc.inspect}"

    now = Time.now
    payload = "#{@user_ustc}:#{now.to_i}"
    set_cookie 'user_ustc', "#{payload}:#{hmac_signature(CONFIG['session_key'], payload)}", now + CONFIG['session_expiry']
    redirect './'
  end

  def auth_github
    unless @req_params['code'] && @req_params['state']
      query = URI.encode_www_form({ client_id: CONFIG['github']['client_id'], redirect_uri: CONFIG['github']['redirect_uri'], state: state })
      return redirect "#{CONFIG['github']['auth_url']}?#{query}"
    end

    uri = URI(CONFIG['github']['validate_url']) # "Accept": "application/json"
    uri.query = URI.encode_www_form({ client_id: CONFIG['github']['client_id'], client_secret: CONFIG['github']['client_secret'], code: @req_params['code'] })
    res = Net::HTTP.post(uri, nil, 'Accept' => 'application/json')
    raise unless res.is_a? Net::HTTPSuccess

    access_token = JSON.parse(res.body)['access_token']
    uri = URI(CONFIG['github']['user_api'])
    req = Net::HTTP::Get.new(uri)
    req['Authorization'] = "token #{access_token}"
    res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') { |http| http.request(req) }
    raise unless res.is_a? Net::HTTPSuccess

    @user_github = JSON.parse(res.body)['login']
    warn "Authenticated with GitHub user #{@user_github.inspect}"

    now = Time.now
    payload = "#{@user_github}:#{now.to_i}"
    set_cookie 'user_github', "#{payload}:#{hmac_signature(CONFIG['session_key'], payload)}", now + CONFIG['session_expiry']
    redirect './'
  end

  def token
    return unless user_ustc && user_github

    payload = "#{user_ustc}:#{user_github}"
    sig = hmac_signature(CONFIG['token_key'], payload)
    @token ||= "#{payload}:#{sig}"
  end

  def validate_token
    return if @req_body.nil? || @req_body.empty?

    content = URI.decode_www_form(@req_body).to_h
    @token = content['token']
    return if @token.nil? || @token.empty?

    unless @token =~ /^\w+:[\w-]+:\w+$/
      @token_valid = false
      @token_reason = 'Bad token format'
      return
    end

    payload, _, sig = @token.rpartition(':')
    hmac = hmac_signature(CONFIG['token_key'], payload)
    if hmac == sig
      @token_valid = true
      @token_ustc, @token_github = payload.split(':')
    else
      @token_valid = false
      @token_reason = 'Bad signature'
    end
  end

  def handle
    case @req_path
    when '/'
      render 'index'
    when '/about'
      render 'about'
    when '/robots.txt'
      @res_body = "User-agent: *\nDisallow: /\n"

    when '/auth-ustc'
      auth_ustc
    when '/auth-github'
      auth_github

    when '/logout'
      set_cookie 'user_ustc'
      set_cookie 'user_github'
      render 'logout'
    when '/logout-ustc'
      redirect CONFIG['cas']['logout']
    when '/logout-github'
      redirect './'

    when '/token'
      render 'token'
    when '/validate'
      validate_token if @req_method == 'POST'
      render 'validate'
    else
      @res_body = "Not found\n"
      @res_code = 404
    end

    [@res_body, @res_code, @res_headers, @res_cookies]
  end
end

# For AWS Lambda invocation
def entrypoint(event:, context:)
  output, status_code, headers, cookies = RequestHandler.new(event).handle

  headers['Content-Type'] ||= 'text/plain'
  mvheaders, headers = headers.partition { |_, v| v.is_a? Array }.map(&:to_h)
  mvheaders.each do |k, v|
    v.each_with_index do |v_, _idx|
      k_ = k.chars.map { |c| c.send(%i[upcase downcase].sample) }.join
      headers[k_] = v_
    end
  end
  { statusCode: status_code, headers: headers, body: output, cookies: cookies }
rescue StandardError => e
  warn ([e.message] + e.backtrace).join $/
  { statusCode: 500, headers: { 'Content-Type' => 'text/plain' }, body: "Internal Server Error\n" }
end

# For command-line invocation
def main
  warn "Invocation URL: #{ARGV[0]}"
  arg_uri = URI(ARGV[0].to_s)
  r = entrypoint(event: {
                   'rawPath' => arg_uri.path,
                   'queryStringParameters' => URI.decode_www_form(arg_uri.query || '').to_h,
                   'headers' => {}
                 }, context: nil)
  if r[:statusCode] == 200
    $stdout.write r[:body]
  else
    p r
  end
end

# Python __name__ == '__main__'
main if $PROGRAM_NAME == __FILE__
