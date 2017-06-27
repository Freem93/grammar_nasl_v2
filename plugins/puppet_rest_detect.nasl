#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66233);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/29 18:11:02 $");

  script_name(english:"Puppet REST API Detection");
  script_summary(english:"Checks for puppet REST web server.");

  script_set_attribute(attribute:"synopsis", value:
"The web service used by an IT automation application was detected on
the remote host.");
  script_set_attribute(attribute:"description", value:
"A Puppet REST API web service, used for communication between masters
and agents, was detected on the remote host");
  # https://docs.puppet.com/puppet/latest/reference/http_api/http_api_index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23685740");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:puppetlabs:puppet");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8139, 8140);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8140);

urls = make_list();

# Not all versions have the same endpoints available. Additionally,
# from version to version, an auth requirement is not consistent
# for a given endpoint. So, many endpoints have been added to 'urls'
# list to cover various cases.

# v1 REST API
environment = strcat(unixtime());
fqdn = get_host_name();

indirection = 'facts'; 
path = '/' + environment + '/' + indirection;
urls[0] = path;

indirection = 'certificate';
path = '/' + environment + '/' + indirection;
urls[1] = path;

# v2 REST API
path = '/v2.0/environments';
urls[2] = path;

# v3 REST API
# puppet enterprise 2015.2.0 and above
path = '/puppet-ca/v1/certificate';
urls[3] = path;

path = '/puppet/v3/facts';
urls[4] = path;

info = NULL;
foreach url (urls)
{
  url = url + '/' + fqdn;
  header = make_array('Accept', 'yaml');
  res = http_send_recv3(
    method:'GET',
    item:url,
    add_headers:header,
    port:port,
    fetch404:TRUE
  );

  info = NULL;

  # beginning of facts response
  if ('--- !ruby/object:Puppet::Node::Facts' >< res[2])
  {
    puppet_error = FALSE;

    facts = make_array(
      'Puppet version', 'puppetversion',
      'Ruby version', 'rubyversion',
      'Operating system', 'operatingsystem',
      'Running as user', 'id',
      'Puppet Agent', 'fact_is_puppetagent',
      'Puppet Master', 'fact_is_puppetmaster',
      'Console', 'fact_is_puppetconsole'
    );

    roles = make_list();

    foreach label (sort(keys(facts)))
    {
      # example response (excerpt):
      #    lsbdistcodename: lucid
      #    uptime_seconds: "9156"
      key = facts[label];
      pattern = '\\s+' + key + ': ("?)(.+)\\1';
      match = eregmatch(string:res[2], pattern:pattern);
      if (isnull(match)) continue;

      if (key =~ '^fact_is_puppet')
        # these properties have boolean
        # values and are used to determine which roles are enabled
      {
        if (match[2] == 'true')
          roles = make_list(roles, label);
      }
      else
      {
        if (key == 'puppetversion')
        {
          # should look like either of the following:
          #   2.7.19 (Puppet Enterprise 2.7.0)
          #   2.7.19
          # make sure the version doesn't look like *id001 or &id002
          ver = match[2];
          match = eregmatch(string:ver, pattern:"([*&]id\d+ )?(\d+\..+)");
          if (!isnull(match))
          {
            info += '\n  ' + label + ' : ' + match[2];
            set_kb_item(name:'puppet/' + port + '/version', value:match[2]);
          }
        }
        else
        {
          if (key == 'rubyversion' && match[2] =~ "^[0-9.]+$")
            set_kb_item(name:'puppet/' + port + '/rubyversion', value:match[2]);

          info += '\n  ' + label + ' : ' + match[2];
        }
      }
    }

    if (max_index(roles) > 0)
    {
      roles = join(roles, sep:', ');
      set_kb_item(name:'puppet/' + port + '/roles', value:roles);
      info += '\n  Roles : ' + roles;
    }
  }
  # Newer versions (3.8.1 and greater at least) block our method
  # with a 'HTTP/1.0 400 Bad Request', however the 'X-Puppet-Version:'
  # HTTP header reveals the version to use
  else if (
    'X-Puppet-Version:' >< res[1] &&
    (
      'Not Found: Could not find environment' >< res[2] ||
      'Not Found: Could not find facts' >< res[2] ||
      'The environment must be purely alphanumeric, not' >< res[2] ||
      '400 Bad Request' >< res[0] ||
      '404 Not Found' >< res[0]   ||
      '-----BEGIN CERTIFICATE-----' >< res[2] # PE 2016.x 
    )
  )
  {
    headers = parse_http_headers(status_line:res[0], headers:res[1]);
    if (!isnull(headers['x-puppet-version']))
    {
      version = headers['x-puppet-version'];
      set_kb_item(name:'puppet/' + port + '/version', value:version);
      info = '\n  ' + version;
      break;
    }
    if (empty_or_null(info))
      audit(
          AUDIT_UNKNOWN_WEB_APP_VER,
          'Puppet REST API',
          build_url(port:port, qs:'/')
      );
  }
  else if (  # error messages that indicate puppet is running
    # the request contained an unknown fqdn
    'Could not find facts ' + fqdn == res[2]
    ||
    # auth required or API is old 
    (
      'Forbidden request' >< res[2]
      &&
      'access to /' + indirection + '/' + fqdn >< res[2]
    )
    ||
    'Could not autoload puppet/indirector/facts/inventory_active_record' >< res[2]  # configuration error
  )
  {
    puppet_error = TRUE;
  }

  if (!isnull(info)) break; # found Puppet REST API
}

if (isnull(info))
  audit(AUDIT_WEB_APP_NOT_INST, 'Puppet REST API', port);

# if the plugin got this far, it knows the REST API web service is
# listening on this port
set_kb_item(name:'puppet/rest_port', value:port);

if (report_verbosity > 0)
{
  # it doesn't make sense to include a URL that the user can click to
  # verify since the request requires sending the "Accept: yaml" HTTP
  # header, which a browser is not going to send by default
  report =
    '\nNessus detected the Puppet REST API by making the following request :\n\n' +
    crap(data:'-', length:30) + " request " + crap(data:'-', length:30) + '\n' +
    chomp(http_last_sent_request()) + '\n' +
    crap(data:'-', length:30) + " request " + crap(data:'-', length:30) + '\n';
  if (puppet_error)
  {
    report +=
      '\nWhich resulted in the following Puppet-specific error :\n\n' +
      chomp(res[2]) +
      '\n';
  }
  else if (!isnull(info))
  {
    report +=
      '\nThe server replied with details about the host, including :\n' +
      info +
      '\n';
  }

  security_note(port:port, extra:report);
}
else security_note(port);
