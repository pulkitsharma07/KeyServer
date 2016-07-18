require 'rubygems'
require 'sinatra'
require 'securerandom'
require 'thread'

require_relative 'keystore'

KS = KeyStore.new

get '/E1' do
  key = KS.gen_key
  "Generated a Key #{key}"
end

get '/E2' do
  key = KS.block_some_key

  if key.nil?
    status 404
  else
    "Blocked #{key}"
  end
end

get '/E3/:key' do
  key = params[:key]
  if KS.unblock(params[:key])
    "Unblocked #{key}"
  else
    status 404
  end
end

get '/E4/:key' do
  key = params[:key]

  if KS.delete_key(key)
    "Deleted Key #{key}"
  else
    status 404
  end
end

get '/E5/:key' do
  key = params[:key]

  if KS.refresh(key)
    "Key refreshed #{key}"
  else
    status 404
  end
end

# Background thread to deal with expiries

Thread.new do
  loop do
    $used_at.each do |key, time|
      if Time.now >= time + KEEP_ALIVE_TIMEOUT
        p key + ' KEY IS EXPIRED'
        KS.delete_key(key)
      end
    end

    $blocked_at.each do |key, time|
      if Time.now >= time + MAX_BLOCK_TIME
        p key + ' KEY IS REALEASED'
        KS.unblock(key)
      end
    end
    sleep 1
  end
end
