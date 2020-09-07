#!/usr/bin/env ruby
# encoding: utf-8

require 'optparse'
require 'httparty'
require 'rbnacl'

def defaultHeaders(token)
    { 'Accept' => '*/*',
      'Content-Type' => 'application/json',
      'Authorization' => 'Bearer ' + token.to_s }
end

def getToken(pia_url, app_key, app_secret)
    auth_url = pia_url.to_s + "/oauth/token"
    response_nil = false
    begin
        response = HTTParty.post(auth_url,
            headers: { 'Content-Type' => 'application/json' },
            body: { client_id: app_key, client_secret: app_secret,
                    grant_type: "client_credentials" }.to_json )
    rescue => ex
        response_nil = true
    end
    if !response_nil && !response.body.nil? && response.code == 200
        return response.parsed_response["access_token"].to_s
    else
        nil
    end
end

def setupApp(pia_url, app_key, app_secret)
    token = getToken(pia_url, app_key, app_secret)
    { :pia_url    => pia_url,
      :app_key    => app_key,
      :app_secret => app_secret,
      :token      => token }
end

def decrypt_message(message, private_key)
    begin
        cipher = [JSON.parse(message)["value"]].pack('H*')
        nonce = [JSON.parse(message)["nonce"]].pack('H*')
        keyHash = RbNaCl::Hash.sha256(private_key.force_encoding('ASCII-8BIT'))
        privateKey = RbNaCl::PrivateKey.new(keyHash)
        authHash = RbNaCl::Hash.sha256('auth'.force_encoding('ASCII-8BIT'))
        authKey = RbNaCl::PrivateKey.new(authHash).public_key
        box = RbNaCl::Box.new(authKey, privateKey)
        box.decrypt(nonce, cipher)
    rescue
        nil
    end
end

options = {}
options[:pia_url] = "https://data-vault.eu"
op = OptionParser.new do |opts|
    opts.banner = "Usage: echo -n '{\"a\": 1}' | encrypt.rb [options]"
    opts.on('-u', '--pia-url [URL]', 'Data Vault URL (default: https://data-vault.eu)') {
        |v| options[:pia_url] = v }
    opts.on('-k', '--app-key KEY', 'Client ID from plugin') {
        |v| options[:app_key] = v }
    opts.on('-s', '--app-secret SECRET', 'Client Secret from plugin') {
        |v| options[:app_secret] = v }
    opts.on('-p', '--password PASSWORD', 'Password to decrypt data') {
        |v| options[:password] = v }
end.parse!
raw_input = ARGF.readlines.join("\n")
if options[:app_key].to_s == "" || options[:app_secret].to_s == "" || options[:password].to_s == "" || raw_input.to_s == ""
    puts op
    abort("Error: missing input and/or parameters")
end
app = setupApp(options[:pia_url],
               options[:app_key],
               options[:app_secret])
if app[:token].to_s == ""
    abort("Error: invalid url and/or credenials")
end
headers = defaultHeaders(app[:token])
key_url = app[:pia_url].to_s + "/api/users/current"
response = HTTParty.get(key_url, headers: headers).parsed_response
privateKey = ""
if response.key?("password_key")
        privateKey = decrypt_message(response["password_key"], options[:password].to_s) rescue ""
end
if privateKey.to_s == ""
        abort("Error: invalid password")
end
puts decrypt_message(raw_input, privateKey)