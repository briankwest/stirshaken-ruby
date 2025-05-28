Gem::Specification.new do |spec|
  spec.name          = "stirshaken"
  spec.version       = "0.1.0"
  spec.authors       = ["Your Name"]
  spec.email         = ["your.email@example.com"]

  spec.summary       = "Ruby implementation of STIR/SHAKEN protocols for caller ID authentication"
  spec.description   = "A comprehensive Ruby library implementing STIR (Secure Telephone Identity Revisited) and SHAKEN (Signature-based Handling of Asserted information using toKENs) protocols for combating caller ID spoofing in telecommunications."
  spec.homepage      = "https://github.com/yourusername/stirshaken-ruby"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 3.0.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/yourusername/stirshaken-ruby"
  spec.metadata["changelog_uri"] = "https://github.com/yourusername/stirshaken-ruby/blob/main/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  spec.files = Dir.glob("{lib,exe}/**/*") + %w[README.md LICENSE.txt CHANGELOG.md SECURITY.md USAGE_GUIDE.md]
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Runtime dependencies
  spec.add_dependency "jwt", "~> 2.7"
  spec.add_dependency "httparty", "~> 0.21"

  # Development dependencies
  spec.add_development_dependency "rspec", "~> 3.12"
  spec.add_development_dependency "webmock", "~> 3.18"
  spec.add_development_dependency "vcr", "~> 6.1"
  spec.add_development_dependency "simplecov", "~> 0.22"
  spec.add_development_dependency "rubocop", "~> 1.50"
  spec.add_development_dependency "yard", "~> 0.9"
end 