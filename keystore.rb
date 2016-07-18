
# keys which are never to be assigned again
$blacklisted_keys = Set.new

# these two hashes will store last used time and blocked_at time ( for blocked) keys
$used_at = {}
$blocked_at = {}

# in seconds
KEEP_ALIVE_TIMEOUT = 300

# in seconds
MAX_BLOCK_TIME = 60

class KeyCollection
  def initialize
    @keys = Set.new
    $expiry = {}
  end

  def include?(x)
    @keys.include?(x)
  end

  def generate
    key = SecureRandom.hex

    while @keys.include?(key) || $blacklisted_keys.include?(key)
      key = SecureRandom.hex
    end

    @keys.add(key)

    $used_at[key] = Time.now

    p @keys

    key
  end

  def random_key
    p @keys.first
    @keys.first
  end

  def add(key)
    @keys.add(key)
  end

  def delete(key)
    @keys.delete(key)
  end

  def delete_forever(key)
    lock = Mutex.new

    lock.synchronize do
      if @keys.include?(key)
        @keys.delete(key)
        $used_at.delete(key)
        $blacklisted_keys.add(key)
        true
      else
        false
      end
    end
  end
end

class KeyStore
  def initialize
    @unblocked_keys = KeyCollection.new
    @blocked_keys = Set.new
  end

  def block_some_key
    lock = Mutex.new

    key = ''
    lock.synchronize do
      key = @unblocked_keys.random_key
      @unblocked_keys.delete(key)
      @blocked_keys.add(key)
      $blocked_at[key] = Time.now
    end

    key
  end

  def unblock(key)
    lock = Mutex.new

    lock.synchronize do
      if @blocked_keys.include?(key)
        @blocked_keys.delete(key)
        $blocked_at.delete(key)
        @unblocked_keys.add(key)
        true
      else
        false
      end
    end
  end

  def delete_key(key)
    deleted = false

    lock = Mutex.new

    lock.synchronize do
      deleted |= @unblocked_keys.delete_forever(key)

      if @blocked_keys.include?(key)
        @blocked_keys.delete(key)
        $used_at.delete(key)
        $blacklisted_keys.add(key)
        deleted = true
      end
    end
    deleted
  end

  def refresh(key)
    if valid_key(key)
      $used_at[key] = Time.now
    else
      false
    end
  end

  def gen_key
    @unblocked_keys.generate
  end

  def valid_key(key)
    @unblocked_keys.include?(key) || @blocked_keys.include?(key)
  end
end
