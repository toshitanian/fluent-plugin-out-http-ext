require 'set'

class Array
  def to_set
    Set.new(self)
  end
end


class Hash
  """
  each traverse in hash
  """
  def each_deep(&proc)
    self.each_deep_detail([], &proc)
  end

  def each_deep_detail(directory, &proc)
    self.each do |k, v|
      current = directory + [k]
      if v.kind_of?(Hash)
        v.each_deep_detail(current, &proc)
      else
        yield(current, v)
      end
    end
  end

end

class StatusCodeParser
  """
  parse status code string to array of codes
  """
  def self.range?(str)
     # i.e. 200..399 => return true
    return /^\d{3}..\d{3}$/ =~ str ? true : false
  end

  def self.number?(str)
    return /^\d{3}$/ =~ str ? true : false
  end

  def self.get_array(str)
    if self.range?(str)
      ends = str.split('..').map{|d| Integer(d)}
      return (ends[0]..ends[1]).to_a
    elsif self.number?(str)
      return [str.to_i]
    else
      raise "invalid status code range format"
    end
  end

  def self.convert(range_str)
    elems = range_str.split(',')
    status_codes = elems.flat_map do |elem|
      self.get_array(elem)
    end
    return status_codes.to_set
  end
end

class Fluent::HTTPOutput < Fluent::Output
  Fluent::Plugin.register_output('http_ext', self)

  def initialize
    super
    require 'net/http'
    require 'uri'
    require 'yajl'
    require 'set'
  end

  # Endpoint URL ex. localhost.local/api/
  config_param :endpoint_url, :string

  # HTTP method
  config_param :http_method, :string, :default => :post

  # form | json
  config_param :serializer, :string, :default => :form

  # true | false
  config_param :use_ssl, :bool, :default => false

  config_param :open_timeout, :integer, :default => nil
  config_param :read_timeout, :integer, :default => 60
  config_param :verify_ssl, :bool, :default => true

  # Simple rate limiting: ignore any records within `rate_limit_msec`
  # since the last one.
  config_param :rate_limit_msec, :integer, :default => 0

  # Raise errors that were rescued during HTTP requests?
  config_param :raise_on_error, :bool, :default => true

  # Raise errors when HTTP response code was not successful.
  config_param :raise_on_http_failure, :bool, :default => false
  config_param :ignore_http_status_code, :string, :default => nil
  # nil | 'none' | 'basic'
  config_param :authentication, :string, :default => nil
  config_param :username, :string, :default => ''
  config_param :password, :string, :default => '', :secret => true

  config_param :format, :string, :default => ''

  def configure(conf)
    super

    serializers = [:json, :form]
    @serializer = if serializers.include? @serializer.intern
                    @serializer.intern
                  else
                    :form
                  end

    http_methods = [:get, :put, :post, :delete]
    @http_method = if http_methods.include? @http_method.intern
                    @http_method.intern
                  else
                    :post
                  end

    @ignore_http_status_code = if @ignore_http_status_code.nil?
                          [].to_set
                        else
                          StatusCodeParser.convert(@ignore_http_status_code)
                        end

    @auth = case @authentication
            when 'basic' then :basic
            else
              :none
            end
    @headers = {}
    conf.elements.each do |element|
      if element.name == 'headers'
        @headers = element.to_hash
      end
    end

    @formatter = nil
    unless @format.empty?
      @formatter = Fluent::Plugin.new_formatter(@format)
      @formatter.configure(conf)
    end
  end

  def start
    super
  end

  def shutdown
    super
  end

  def format_url(tag, time, record)
    '''
    replace format string to value
    example
      /test/<data> =(use {data: 1})> /test/1
      /test/<hash.data> =(use {hash:{data:2}})> /test/2
    '''
    result_url = @endpoint_url
    return result_url unless record.is_a? Hash
    record.each_deep do |key_dir, value|
      result_url = result_url.gsub(/<#{key_dir.join(".")}>/, value.to_s)
    end
    return result_url
  end

  def set_body(req, tag, time, record)
    if @serializer == :json
      set_json_body(req, record)
    else
      req.set_form_data(record)
    end
    req
  end

  def set_header(req, tag, time, record)
    @headers.each do |key, value|
      req[key] = value
    end
    req
  end

  def set_json_body(req, data)
    req.body = Yajl.dump(data)
    req['Content-Type'] = 'application/json'
  end

  def create_request(tag, time, record)
    url = format_url(tag, time, record)
    uri = URI.parse(url)
    req = Net::HTTP.const_get(@http_method.to_s.capitalize).new(uri.path)
    set_body(req, tag, time, record)
    set_header(req, tag, time, record)
    return req, uri
  end

  def send_request(req, uri)
    is_rate_limited = (@rate_limit_msec != 0 and not @last_request_time.nil?)
    if is_rate_limited and ((Time.now.to_f - @last_request_time) * 1000.0 < @rate_limit_msec)
      $log.info('Dropped request due to rate limiting')
      return
    end

    res = nil

    begin
      if @auth and @auth == :basic
        req.basic_auth(@username, @password)
      end
      @last_request_time = Time.now.to_f
      client = Net::HTTP.new(uri.host, uri.port)
      if @use_ssl
        client.use_ssl = true
        client.ca_file = OpenSSL::X509::DEFAULT_CERT_FILE
        unless @verify_ssl
          client.verify_mode = OpenSSL::SSL::VERIFY_NONE
        end
      end
      res = client.start {|http|
        http.open_timeout = @open_timeout
        http.read_timeout = @read_timeout
        http.request(req)
      }
    rescue => e # rescue all StandardErrors
      # server didn't respond
      $log.warn "Net::HTTP.#{req.method.capitalize} raises exception: #{e.class}, '#{e.message}'"
      raise e if @raise_on_error
    else
       unless res and res.is_a?(Net::HTTPSuccess)
          res_summary = if res
                           "#{res.code} #{res.message} #{res.body}"
                        else
                           "res=nil"
                        end
          warning = "failed to #{req.method} #{req.to_hash.inspect} #{uri} (#{res_summary})"
          $log.warn warning
          if @raise_on_http_failure
            unless @ignore_http_status_code.include?(res.code.to_i)
              raise warning
            else
              $log.debug "ignore http status code #{req.method}"
            end
          end

       end #end unless
    end # end begin
  end # end send_request

  def handle_record(tag, time, record)
    req, uri = create_request(tag, time, record)
    send_request(req, uri)
  end

  def emit(tag, es, chain)
    es.each do |time, record|
      if @formatter
        record = @formatter.format(tag, time, record)
      end
      handle_record(tag, time, record)
    end
    chain.next
  end
end
