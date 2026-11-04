require 'net/http'
require 'uri'
require 'json'
require 'openssl'
begin
  uri = URI(ARGV[-2]); timeout = ARGV[-1].to_f
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.open_timeout = timeout; http.read_timeout = timeout
  response = http.start { |h| h.request(Net::HTTP::Get.new(uri.request_uri)) }
  puts 'EMUDHRA_JSON:' + {state:'accepted', detail:'HTTP '+response.code}.to_json
rescue Exception => e
  puts 'EMUDHRA_JSON:' + {state:'error', detail:e.class.name+': '+e.message}.to_json
end
