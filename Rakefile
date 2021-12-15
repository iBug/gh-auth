# frozen_string_literal: true

require 'aws-sdk-lambda'
require 'rake/clean'
require 'zip'

ZIP_FILE = 'package.zip'
FILES = %w[main.rb config.yml] + Dir.glob('templates/**')
CLEAN.include ZIP_FILE

task :default => :deploy
task :deploy => %i[clean publish]

file ZIP_FILE do
  Zip::File.open ZIP_FILE, Zip::File::CREATE do |zipfile|
    FILES.each do |f|
      zipfile.add f, f
    end
  end
end

task :publish => ZIP_FILE do
  File.open ZIP_FILE, 'rb' do |f|
    Aws::Lambda::Client.new.update_function_code({
      function_name: ENV['AWS_FUNCTION_NAME'] || 'GHAuth',
      zip_file: f,
      publish: true,
    })
  end
end
