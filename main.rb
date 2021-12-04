#!/usr/bin/ruby
# frozen_string_literal: true

require 'base64'
require 'cgi'
require 'erb'
require 'json'
require 'net/http'
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
      @base ||= self.new
    end
  end
end

module ERBHelper
  def h(s)
    CGI::escapeHTML s
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

  def cookies
    @cookies ||= CGI::Cookie.parse(@req_headers['Cookie'])
  end

  def id_from_cookie(cookie_name)
    id, timestamp, sig = cookies[cookie_name].split('+')
    hmac = hmac_sha1(CONFIG['session_key'], "#{id}+#{timestamp}")
    fail unless hmac == sig
    fail unless Time.now.to_i < timestamp.to_i + CONFIG['session_expiry']
    id
  rescue
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
    end

    [@res_body, @res_code, @res_headers]
  end
end

# For AWS Lambda invocation
def entrypoint(event:, context:)
  url_path = event['rawPath']
  query_params = event['queryStringParameters'] || {}
  output, status_code, headers = RequestHandler.new(url_path, query_params, event['headers']).handle

  headers['Content-Type'] ||= 'text/html'
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
                   'queryStringParameters' => arg_uri.query && URI.decode_www_form(arg_uri.query).to_h,
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
