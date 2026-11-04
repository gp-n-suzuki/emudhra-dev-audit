# Loaded into the selected package manager, not a substitute HTTP client.
# Observe the original socket without changing its CA store, verification,
# callbacks, TLS versions, HTTP requests, redirects, or exception behavior.
require 'openssl'
require 'json'

module EmudhraConnectionObserver
  @count = 0
  @lock = Mutex.new

  def self.linked_chain(socket)
    leaf = socket.peer_cert
    return [] unless leaf
    chain = [leaf]
    candidates = (socket.peer_cert_chain || []).take(16)
    while chain.length < 16
      child = chain[-1]
      parent = candidates.find do |candidate|
        !chain.any? { |seen| seen.to_der == candidate.to_der } &&
          child.issuer == candidate.subject && child.verify(candidate.public_key)
      end
      break unless parent
      chain << parent
    end
    chain
  end

  def self.record(socket, state)
    return if socket.instance_variable_get(:@emudhra_recorded)
    socket.instance_variable_set(:@emudhra_recorded, true)
    destination = ENV['EMUDHRA_TLS_EVIDENCE']
    return unless destination && !destination.empty?
    host = socket.hostname
    return unless host.is_a?(String) && host.length <= 253
    code = socket.verify_result
    chain = linked_chain(socket)
    pins = chain.take(16).map do |cert|
      # Extract SubjectPublicKeyInfo from the certificate. Old Ruby OpenSSL
      # lacks PKey#public_to_der and RSA#to_der may instead encode PKCS#1.
      fields = OpenSSL::ASN1.decode(cert.to_der).value[0].value
      index = fields[0].tag_class == :CONTEXT_SPECIFIC ? 6 : 5
      OpenSSL::Digest::SHA256.hexdigest(fields[index].to_der)
    end
    name_ok = state == 'accepted' && socket.peer_cert &&
      OpenSSL::SSL.verify_certificate_identity(socket.peer_cert, host)
    fact = {schema: 1, source: 'ruby_ssl_socket', host: host.downcase,
            port: socket.to_io.peeraddr(false)[1], state: state,
            verify_code: code, verify_peer: (socket.context.verify_mode & OpenSSL::SSL::VERIFY_PEER) != 0,
            hostname_verified: !!name_ok, chain_spki_sha256: pins}
    @lock.synchronize do
      if @count < 64
        File.open(destination, 'a', 0600) { |file| file.puts(JSON.generate(fact)) }
        @count += 1
      elsif @count == 64
        File.open(destination, 'a', 0600) { |file| file.puts(JSON.generate({schema: 1, source: 'ruby_ssl_socket', state: 'overflow'})) }
        @count += 1
      end
    end
  rescue StandardError
    # A missing observation must not change the package manager's behavior.
    nil
  end

  module SocketMethods
    def connect(*args, **options)
      result = super
      EmudhraConnectionObserver.record(self, 'accepted') if result.equal?(self)
      result
    rescue OpenSSL::SSL::SSLError => error
      raise if error.is_a?(IO::WaitReadable) || error.is_a?(IO::WaitWritable)
      EmudhraConnectionObserver.record(self, 'error')
      raise
    end

    def connect_nonblock(*args, **options)
      result = super
      EmudhraConnectionObserver.record(self, 'accepted') if result.equal?(self)
      result
    rescue OpenSSL::SSL::SSLError => error
      raise if error.is_a?(IO::WaitReadable) || error.is_a?(IO::WaitWritable)
      EmudhraConnectionObserver.record(self, 'error')
      raise
    end
  end
end

OpenSSL::SSL::SSLSocket.prepend(EmudhraConnectionObserver::SocketMethods)
