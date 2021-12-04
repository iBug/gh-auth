#!/usr/bin/ruby
# frozen_string_literal: true

require 'base64'
require 'cgi'
require 'erb'
require 'net/http'
require 'ostruct'
require 'time'
require 'json'
require 'yaml'

TEMPLATE_DIR = 'templates'
CONFIG = YAML.load_file('config.yml')

class Template
  def initialize(name = 'base')
    @template = Template.get(name)
  end

  def self.get(name)
    ERB.new(File.read(File.join(TEMPLATE_DIR, "#{name}.erb")))
  end

  def render
    @template.result(binding)
  end
end

BASE_TEMPLATE = Template.new

def render(filename)
  BASE_TEMPLATE.render do
    Template.get(filename).result(binding)
  end
end

class RequestHandler
  def initialize(url_key, queryParams, headers)
    @url_key = url_key
    @queryParams = queryParams
    @headers = headers
  end

  def session_info
    return {} unless @headers['cookie']
    CGI::Cookie.parse(@headers['cookie'])
  end

  def handle
    @session = session_info
    case @url_key
    when ''
      render 'index'
    end
  end
end

def entrypoint(event:, context:)
  key = event['rawPath'].delete_prefix '/'
  queryParams = event['queryStringParameters'] || {}
  output, status_code, headers = RequestHandler.new(key, queryParams, event['headers']).handle

  status_code ||= 200
  headers ||= {}
  headers['Content-Type'] ||= 'text/html'
  { statusCode: status_code, headers: headers, body: output }
rescue StandardError => e
  warn ([e.message] + e.backtrace).join $/
  { statusCode: 500, headers: { 'Content-Type' => 'text/plain' }, body: "Internal Server Error\n" }
end

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
