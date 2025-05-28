# frozen_string_literal: true

require 'spec_helper'

RSpec.describe StirShaken::Attestation do
  describe 'constants' do
    it 'defines correct attestation levels' do
      expect(StirShaken::Attestation::FULL).to eq('A')
      expect(StirShaken::Attestation::PARTIAL).to eq('B')
      expect(StirShaken::Attestation::GATEWAY).to eq('C')
    end

    it 'defines valid levels array' do
      expect(StirShaken::Attestation::VALID_LEVELS).to eq(['A', 'B', 'C'])
      expect(StirShaken::Attestation::VALID_LEVELS).to be_frozen
    end
  end

  describe '.valid?' do
    it 'returns true for valid attestation levels' do
      expect(StirShaken::Attestation.valid?('A')).to be true
      expect(StirShaken::Attestation.valid?('B')).to be true
      expect(StirShaken::Attestation.valid?('C')).to be true
    end

    it 'returns false for invalid attestation levels' do
      expect(StirShaken::Attestation.valid?('D')).to be false
      expect(StirShaken::Attestation.valid?('X')).to be false
      expect(StirShaken::Attestation.valid?('1')).to be false
      expect(StirShaken::Attestation.valid?('')).to be false
      expect(StirShaken::Attestation.valid?(nil)).to be false
      expect(StirShaken::Attestation.valid?('a')).to be false
      expect(StirShaken::Attestation.valid?('AA')).to be false
    end
  end

  describe '.validate!' do
    it 'returns the level for valid attestation levels' do
      expect(StirShaken::Attestation.validate!('A')).to eq('A')
      expect(StirShaken::Attestation.validate!('B')).to eq('B')
      expect(StirShaken::Attestation.validate!('C')).to eq('C')
    end

    it 'raises InvalidAttestationError for invalid levels' do
      expect {
        StirShaken::Attestation.validate!('D')
      }.to raise_error(StirShaken::InvalidAttestationError, /Invalid attestation level: D/)

      expect {
        StirShaken::Attestation.validate!('X')
      }.to raise_error(StirShaken::InvalidAttestationError, /Invalid attestation level: X/)

      expect {
        StirShaken::Attestation.validate!(nil)
      }.to raise_error(StirShaken::InvalidAttestationError, /Invalid attestation level:/)

      expect {
        StirShaken::Attestation.validate!('')
      }.to raise_error(StirShaken::InvalidAttestationError, /Invalid attestation level:/)
    end

    it 'includes valid levels in error message' do
      expect {
        StirShaken::Attestation.validate!('X')
      }.to raise_error(StirShaken::InvalidAttestationError, /Must be one of: A, B, C/)
    end
  end

  describe '.description' do
    it 'returns correct descriptions for valid levels' do
      expect(StirShaken::Attestation.description('A')).to eq(
        'Full Attestation - Service provider has authenticated the calling party and verified authorization'
      )

      expect(StirShaken::Attestation.description('B')).to eq(
        'Partial Attestation - Service provider has authenticated call origination but cannot verify caller authorization'
      )

      expect(StirShaken::Attestation.description('C')).to eq(
        'Gateway Attestation - Service provider has authenticated the gateway but cannot authenticate the call source'
      )
    end

    it 'returns unknown description for invalid levels' do
      expect(StirShaken::Attestation.description('D')).to eq('Unknown attestation level')
      expect(StirShaken::Attestation.description('X')).to eq('Unknown attestation level')
      expect(StirShaken::Attestation.description(nil)).to eq('Unknown attestation level')
      expect(StirShaken::Attestation.description('')).to eq('Unknown attestation level')
    end
  end

  describe '.confidence_level' do
    it 'returns correct confidence levels for valid attestations' do
      expect(StirShaken::Attestation.confidence_level('A')).to eq(100)
      expect(StirShaken::Attestation.confidence_level('B')).to eq(75)
      expect(StirShaken::Attestation.confidence_level('C')).to eq(50)
    end

    it 'returns 0 for invalid attestation levels' do
      expect(StirShaken::Attestation.confidence_level('D')).to eq(0)
      expect(StirShaken::Attestation.confidence_level('X')).to eq(0)
      expect(StirShaken::Attestation.confidence_level(nil)).to eq(0)
      expect(StirShaken::Attestation.confidence_level('')).to eq(0)
      expect(StirShaken::Attestation.confidence_level('1')).to eq(0)
    end
  end

  describe 'integration with other components' do
    it 'works with constants in other modules' do
      expect(StirShaken::Attestation.valid?(StirShaken::Attestation::FULL)).to be true
      expect(StirShaken::Attestation.valid?(StirShaken::Attestation::PARTIAL)).to be true
      expect(StirShaken::Attestation.valid?(StirShaken::Attestation::GATEWAY)).to be true
    end

    it 'provides consistent confidence levels' do
      full_confidence = StirShaken::Attestation.confidence_level(StirShaken::Attestation::FULL)
      partial_confidence = StirShaken::Attestation.confidence_level(StirShaken::Attestation::PARTIAL)
      gateway_confidence = StirShaken::Attestation.confidence_level(StirShaken::Attestation::GATEWAY)

      expect(full_confidence).to be > partial_confidence
      expect(partial_confidence).to be > gateway_confidence
      expect(gateway_confidence).to be > 0
    end
  end

  describe 'edge cases' do
    it 'handles case sensitivity correctly' do
      expect(StirShaken::Attestation.valid?('a')).to be false
      expect(StirShaken::Attestation.valid?('b')).to be false
      expect(StirShaken::Attestation.valid?('c')).to be false
    end

    it 'handles whitespace correctly' do
      expect(StirShaken::Attestation.valid?(' A')).to be false
      expect(StirShaken::Attestation.valid?('A ')).to be false
      expect(StirShaken::Attestation.valid?(' A ')).to be false
    end

    it 'handles numeric strings correctly' do
      expect(StirShaken::Attestation.valid?('0')).to be false
      expect(StirShaken::Attestation.valid?('1')).to be false
      expect(StirShaken::Attestation.valid?('2')).to be false
    end
  end
end 