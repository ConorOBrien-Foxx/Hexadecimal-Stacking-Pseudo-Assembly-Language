#!/usr/bin/env ruby

# modified by Conor O'Brien from
# https://gist.github.com/0x0dea/b243ecaaaedaaa58b264

class HSPAL
  # Enforce unsigned 16-bit data by clamping all entries.
  class Stack < Array
    def << val
      super [0, val, 0xFFFF].sort[1]
    end
  end

  Guards = {1 => [*2..3, 0x12,  0x13, 0x41, 0x42],
            2 => [*0x21..0x25, *0x30..0x35]}

  def initialize src = ARGF.read
    @instructions = src.gsub(/(;.*?$)|\s/m,"").gsub(/\H/,"").scan(/\h{6}/).map { |hex| [hex].pack('H6').bytes }
  end

  def run
    ip, reg, labels = -1, 0, {}
    @MEMORY = Array.new(256) { Stack.new }

    while (ip += 1) < @instructions.size
      op, a, b = @instructions[ip]
      c = a * 256 + b

      Guards.each do |min, cov|
        if cov.include?(op) && @MEMORY[a].size < min
           p [op, @MEMORY[a], min]
          raise "Too few stack items for opcode #{op}!"
        end
      end

      case op
        # flow control
      when 0x00; labels[c] = ip
      when 0x01; raise "Nonexistent label!" unless ip = labels[c]
      when 0x02; raise "Nonexistent label!" unless ip = labels[@MEMORY[a].pop]
      when 0x03; ip += 1 if @MEMORY[a].pop > 0
      when 0x04; raise "Halted with status #{c}."

        # IO
      when 0x10; @MEMORY[a] << (STDIN.getc || 0).ord
      when 0x11; @MEMORY[a] << gets.to_i
      when 0x12; print @MEMORY[a].pop
      when 0x13; print '' << @MEMORY[a].pop
      when 0x14; print '' << @MEMORY[a].pop until @MEMORY[a].empty?

        # arithmetic
      when 0x20; reg = c
      when 0x21..0x25
        n, m = @MEMORY[a].pop(2)
        @MEMORY[a] << m.send(%w[+ - * / **][op - 0x21], n)
      when 0x26; reg = rand(c)

        # logic
      when 0x30..0x35
        n, m = @MEMORY[a].pop(2)
        @MEMORY[b] << (m.send(%w[== > < | & ^][op - 0x30], n) ? 1 : 0)   
      when 0x36; @MEMORY[a] << reg == 0 ? 1 : 0

        # misc
      when 0x40; @MEMORY[a] << reg and reg = 0
      when 0x41..0x43
        reg = @MEMORY[a].send %w[pop last size][op - 0x41]

      else raise "Illegal opcode: #{op} "
      end
    end
  end
end

HSPAL.new(File.read ARGV[0]).run