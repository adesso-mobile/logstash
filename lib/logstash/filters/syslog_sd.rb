require "logstash/filters/base"
require "logstash/namespace"

# Filter plugin for logstash to parse the STRUCTURED-DATA field from
# a Syslog (RFC5424) message.
#
class LogStash::Filters::Syslog_SD < LogStash::Filters::Base
  config_name "syslog_sd"

  # set the status to experimental/beta/stable
  plugin_status "experimental"

  # Name of field which passes in the extracted STRUCTURED-DATA part of the syslog message
  config :syslog5424_sd_field_name, :validate => :string, :default => "syslog5424_sd"

  public
  def register
    # This space intentionally left blank.
  end # def register

  public
  def filter(event)
    return unless filter?(event)
    parse_sd(event)
    filter_matched(event)
  end # def filter

  private
  def parse_sd(event)
    if event.fields[@syslog5424_sd_field_name]
      if event.fields[@syslog5424_sd_field_name].is_a?(Array)
        sd = event.fields[@syslog5424_sd_field_name].first
      else
        sd = event.fields[@syslog5424_sd_field_name]
      end

      syslog5424_sd = {}

      # split STRUCTURED-DATA block into separate SD-ELEMENTs
      sd.scan(/\[.*?\]/).each do |sd_elem|

        # strip brackets ('[.*?]') and split SD-ID and SD-PARAMS
        sd_id, sep, params = sd_elem[1, sd_elem.length - 1].partition(' ')

        sd_params = {}
        # split SD-PARAMS block into separate SD-PARAMs
        params.scan(/\w+=".*?"+/).each do |sd_param|

          # split each SD-PARAM into PARAM-NAME and PARAM-VALUE
          param_name, sep, param_value = sd_param.partition('=')

          # store each pair in hash, stripping quotes from PARAM-VALUE
          sd_params[param_name] = param_value[1, param_value.length - 1]

        end
        syslog5424_sd[sd_id] = (sd_params.empty? ? nil : sd_params)
      end
      event.fields[@syslog5424_sd_field_name] = syslog5424_sd unless syslog5424_sd.empty?
    end
  end # def parse_sd
end # class LogStash::Filters::Syslog_sd
