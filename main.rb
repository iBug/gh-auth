#!/usr/bin/ruby
# frozen_string_literal: true

require 'base64'
require 'cgi'
require 'erb'
require 'json'
require 'net/http'
require 'nokogiri'
require 'openssl'
require 'securerandom'
require 'time'
require 'yaml'

TEMPLATE_DIR = 'templates'
CONFIG = YAML.load_file('config.yml')

def hmac_sha1(key, data)
  digest = OpenSSL::Digest.new('sha1')
  OpenSSL::HMAC.hexdigest(digest, key, data)
end

def admins
  CONFIG['admins']
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

module ERBHelper
  def h(s)
    CGI.escapeHTML s
  end
end

class RequestHandler
  extend ERBHelper

  def initialize(req_path, req_params, req_headers)
    @req_path = req_path
    @req_params = req_params
    @req_headers = req_headers

    @res_body = ''
    @res_code = 200
    @res_headers = { 'Content-Type' => 'text/plain' }
  end

  def render(template)
    @res_body = Template.base.render do
      Template.get(template).result(binding)
    end
    @res_headers['Content-Type'] = 'text/html'
  end

  def redirect(target, code=302)
    @res_code = code
    @res_headers['Location'] = target
  end

  def cookies
    @cookies ||= CGI::Cookie.parse(@req_headers['Cookie'])
  end

  def set_cookie(name, value = nil, expires = nil)
    expires ||= Time.now + CONFIG['session_expiry']
    if value.nil?
      value = ''
      expires = Time.at(0)
    end
    @res_headers['Set-Cookie'] ||= []
    @res_headers['Set-Cookie'] << CGI::Cookie.new('name' => name, 'value' => value, 'path' => '/', 'expires' => expires).to_s
  end

  def id_from_cookie(cookie_name)
    return unless cookies.key? cookie_name
    id, timestamp, sig = cookies[cookie_name].split('+')
    hmac = hmac_sha1(CONFIG['session_key'], "#{id}+#{timestamp}")
    raise unless hmac == sig
    raise unless Time.now.to_i < timestamp.to_i + CONFIG['session_expiry']

    id
  rescue StandardError => e
    set_cookie cookie_name
  end

  def user_ustc
    @user_ustc ||= id_from_cookie 'user_ustc'
  end

  def user_github
    @user_github ||= id_from_cookie 'user_github'
  end

  def handle
    case @req_path
    when '/'
      render 'index'
    when '/robots.txt'
      @res_body = "User-agent: *\nDisallow: /\n"
    when '/logout'
      set_cookie 'user_ustc', '', Time.at(0)
      set_cookie 'user_github', '', Time.at(0)
      render 'logout'
    when '/logout-ustc'
      redirect CONFIG['cas']['logout']
    when '/logout-github'
      redirect './'
    else
      @res_body = "Not found\n"
      @res_code = 404
    end

    [@res_body, @res_code, @res_headers]
  end
end

# For AWS Lambda invocation
def entrypoint(event:, context:)
  url_path = event['rawPath']
  query_params = event['queryStringParameters'] || {}
  output, status_code, headers = RequestHandler.new(url_path, query_params, event['headers']).handle

  headers['Content-Type'] ||= 'text/plain'
  mvheaders, headers = headers.partition { |_, v| v.is_a? Array }.map(&:to_h)
  mvheaders.each do |k, v|
    v.each_with_index do |v_, idx|
      k_ = k.chars.map { |c| c.send(%i[upcase downcase].sample) }.join
      headers[k_] = v_
    end
  end
  { statusCode: status_code, headers: headers, body: output }
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
                 }, context: {})
  if r[:statusCode] == 200
    $stdout.write r[:body]
  else
    p r
  end
end

# Python __name__ == '__main__'
main if $PROGRAM_NAME == __FILE__
