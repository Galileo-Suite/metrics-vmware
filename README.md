# Metrics::Vmware

Ruby script/gem to capture VMware vCenter performace metrics.

## Installation

Clone this repo:
`git clone https://github.com/vgcrld/metrics-vmware.git`

Move to the directory:
`cd metrics-vmware`

Install the bundle: 
`bundle install`

## Usage

You can show or get metrics by using the `--get` or `--show` flags.

```bash
bundle exec metrics-vmware --help
Options:
  -s, --server=<s>      vCenter IP or FQN
  -u, --user=<s>        vCenter User
  -p, --password=<s>    Password
  -o, --port=<i>        Port (default: 443)
  -i, --id=<s>          Metrics to Get (Regexp `name`) (default: ^(cpu|mem)\.usage\.average)
  -g, --get             Get the Perf data
  -h, --show            Show the Perf IDs
  -f, --file=<s>        Output json file (default: /Users/rdavis/vmware-1649186749.json)
  -e, --help            Show this message
```

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
