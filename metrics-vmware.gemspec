require_relative 'lib/metrics/vmware/version'

Gem::Specification.new do |spec|
  spec.name          = "metrics-vmware"
  spec.version       = Metrics::Vmware::VERSION
  spec.authors       = ["Rich Davis"]
  spec.email         = ["rdavis@galileosuite.com"]

  spec.summary       = %q{Get VMware metrics from vCenter}
  spec.description   = %q{Use the vsphere API to pull metrics using Ruby}
  spec.homepage      = "https://github.com/vgcrld/metrics-vmware"
  spec.license       = "MIT"
  spec.required_ruby_version = Gem::Requirement.new(">= 2.3.0")

  # spec.metadata["allowed_push_host"] = "TODO: Set to 'http://mygemserver.com'"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/vgcrld/metrics-vmware"
  spec.metadata["changelog_uri"] = "https://github.com/vgcrld/metrics-vmware"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency 'optimist'
  spec.add_dependency 'rbvmomi'
  spec.add_dependency 'awesome_print'
  
end
