# frozen_string_literal: true

require 'faraday'
require 'multipart/post'
require 'set'

Faraday.const_set(:UploadIO, Multipart::Post::UploadIO) unless Faraday.const_defined?(:UploadIO, false)

module FaradayMiddleware
  class RedirectLimitReached < Faraday::ClientError
    attr_reader :response

    def initialize(response)
      super("too many redirects; last one to: #{response['location']}")
      @response = response
    end
  end

  class FollowRedirects < Faraday::Middleware
    ALLOWED_METHODS = Set.new(%i[head options get post put patch delete])
    REDIRECT_CODES = Set.new([301, 302, 303, 307, 308])
    ENV_TO_CLEAR = Set.new(%i[status response response_headers])
    FOLLOW_LIMIT = 3
    URI_UNSAFE = %r{[^\-_.!~*'()a-zA-Z\d;/?:@&=+$,\[\]%]}.freeze
    AUTH_HEADER = 'Authorization'

    def initialize(app, options = {})
      super(app)
      @options = options
      @convert_to_get = Set.new([303])
      @convert_to_get << 301 << 302 unless standards_compliant?
    end

    def call(env)
      perform_with_redirection(env, follow_limit)
    end

    private

    def convert_to_get?(response)
      !%i[head options].include?(response.env[:method]) && @convert_to_get.include?(response.status)
    end

    def perform_with_redirection(env, follows)
      request_body = env[:body]
      response = @app.call(env)

      response.on_complete do |response_env|
        if follow_redirect?(response_env, response)
          raise RedirectLimitReached, response if follows.zero?

          new_request_env = update_env(response_env.dup, request_body, response)
          callback&.call(response_env, new_request_env)
          response = perform_with_redirection(new_request_env, follows - 1)
        end
      end

      response
    end

    def update_env(env, request_body, response)
      redirect_from_url = env[:url].to_s
      redirect_to_url = safe_escape(response['location'] || '')
      env[:url] += redirect_to_url

      ENV_TO_CLEAR.each { |key| env.delete(key) }

      if convert_to_get?(response)
        env[:method] = :get
        env[:body] = nil
      else
        env[:body] = request_body
      end

      clear_authorization_header(env, redirect_from_url, redirect_to_url)
      env
    end

    def follow_redirect?(env, response)
      ALLOWED_METHODS.include?(env[:method]) && REDIRECT_CODES.include?(response.status)
    end

    def follow_limit
      @options.fetch(:limit, FOLLOW_LIMIT)
    end

    def standards_compliant?
      @options.fetch(:standards_compliant, false)
    end

    def callback
      @options[:callback]
    end

    def safe_escape(uri)
      uri = uri.split('#')[0]
      uri.to_s.gsub(URI_UNSAFE) do |match|
        "%#{match.unpack('H2' * match.bytesize).join('%').upcase}"
      end
    end

    def clear_authorization_header(env, from_url, to_url)
      return env if redirect_to_same_host?(from_url, to_url)
      return env unless @options.fetch(:clear_authorization_header, true)

      env[:request_headers].delete(AUTH_HEADER)
    end

    def redirect_to_same_host?(from_url, to_url)
      return true if to_url.start_with?('/')

      from_uri = URI.parse(from_url)
      to_uri = URI.parse(to_url)

      [from_uri.scheme, from_uri.host, from_uri.port] == [to_uri.scheme, to_uri.host, to_uri.port]
    end
  end

  class ResponseMiddleware < Faraday::Middleware
    CONTENT_TYPE = 'Content-Type'

    class << self
      attr_accessor :load_error, :parser
    end

    def self.dependency
      yield
    rescue LoadError => e
      self.load_error = e
    end

    def self.define_parser(parser = nil, &block)
      @parser = parser || block || raise(ArgumentError, 'Define parser with a block')
    end

    def self.inherited(subclass)
      super
      subclass.load_error = load_error if subclass.respond_to?(:load_error=)
      subclass.parser = parser
    end

    def initialize(app = nil, options = {})
      raise self.class.load_error if self.class.load_error

      super(app)
      @options = options
      @parser_options = options[:parser_options]
      @content_types = Array(options[:content_type])
    end

    def call(env)
      @app.call(env).on_complete do |response_env|
        type = response_type(response_env)
        process_response(response_env) if process_response_type?(type) && parse_response?(response_env)
      end
    end

    def process_response(env)
      env[:raw_body] = env[:body] if preserve_raw?(env)
      env[:body] = parse(env[:body])
    rescue Faraday::ParsingError => e
      raise Faraday::ParsingError.new(e.wrapped_exception, env[:response])
    end

    def parse(body)
      return body unless self.class.parser

      self.class.parser.call(body, @parser_options)
    rescue StandardError, SyntaxError => e
      raise e if e.is_a?(SyntaxError) && e.class.name != 'Psych::SyntaxError'

      raise Faraday::ParsingError, e
    end

    def response_type(env)
      type = env[:response_headers][CONTENT_TYPE].to_s
      type = type.split(';', 2).first if type.index(';')
      type
    end

    def process_response_type?(type)
      @content_types.empty? || @content_types.any? do |pattern|
        pattern.is_a?(Regexp) ? type =~ pattern : type == pattern
      end
    end

    def parse_response?(env)
      env[:body].respond_to?(:to_str)
    end

    def preserve_raw?(env)
      env[:request].fetch(:preserve_raw, @options[:preserve_raw])
    end
  end
end

Faraday::Response.register_middleware(follow_redirects: -> { FaradayMiddleware::FollowRedirects })
