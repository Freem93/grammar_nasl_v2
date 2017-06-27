#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62565);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/09/26 02:31:57 $");

  script_cve_id("CVE-2012-4929", "CVE-2012-4930");
  script_bugtraq_id(55704, 55707);
  script_osvdb_id(85926, 85927);

  script_name(english:"Transport Layer Security (TLS) Protocol CRIME Vulnerability");
  script_summary(english:"Checks whether requirements for CRIME attack are present.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service has a configuration that may make it vulnerable to
the CRIME attack.");
  script_set_attribute(attribute:"description", value:
"The remote service has one of two configurations that are known to be
required for the CRIME attack :

  - SSL / TLS compression is enabled.

  - TLS advertises the SPDY protocol earlier than version 4.

Note that Nessus did not attempt to launch the CRIME attack against the
remote service.");
  script_set_attribute(attribute:"see_also", value:"http://www.iacr.org/cryptodb/data/paper.php?pubkey=3091");
  script_set_attribute(attribute:"see_also", value:"https://discussions.nessus.org/thread/5546");
   # http://threatpost.com/new-attack-uses-ssltls-information-leak-hijack-https-sessions-090512/76973
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ec18eb5");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/bugzilla/show_bug.cgi?id=53219");
  script_set_attribute(attribute:"solution", value:"Disable compression and / or the SPDY service.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_compression.nasl", "ssl_supported_protocols.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

get_kb_item_or_exit("SSL/Supported");

# Get a port to operate on, forking for each one.
port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

proto = get_kb_list("SSL/Protocols/" + port);
if ( !isnull(proto) ) proto = make_list(proto);
item = NULL;
if ( ! isnull(proto) )
{
 foreach item ( proto )
 {
  if ( item =~ "^spdy" ) break;
 }
}

if ( isnull(proto) || item !~ "^spdy" )
{
 www = get_kb_list("Services/www");
 if (isnull(www) )
  exit(1, "The host is not running a web server.");

 foreach item (make_list(www))
 {
  if ( item == port )  break;
 }

 if ( item != port )
   exit(0, "Port " + port + " is not running a web server.");
}

# Get the list of compression methods.
compression = FALSE;
compressors = get_kb_list("SSL/Compressors/" + port);
if (!isnull(compressors))
{
  foreach compressor (compressors)
  {
    # Any compression method other than NULL is affected.
    if (compressor != 0x00)
    {
      compression = TRUE;
      break;
    }
  }
}

# Get the list of advertised protocols.
spdy = FALSE;
protocols = get_kb_list("SSL/Protocols/" + port);
if (!isnull(protocols))
{
  foreach protocol (protocols)
  {
    # Version 4 will fix CRIME.
    if (protocol =~ "^spdy/[0-3](\.|$)")
    {
      spdy = TRUE;
      break;
    }
  }
}

# Check if the service is affected.
if (!compression && !spdy)
  exit(0, "The service on port " + port + " has neither SPDY advertised nor compression enabled and is therefore unaffected.");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\nThe following configuration indicates that the remote service' +
    '\nmay be vulnerable to the CRIME attack :';

  if (compression)
  {
    report +=
      '\n' +
      '\n  - SSL / TLS compression is enabled.' +
      '\n';
  }

  if (spdy)
  {
    report +=
      '\n' +
      '\n  - SPDY support earlier than version 4 is advertised.' +
      '\n';
  }
}

security_warning(port:port, extra:report);
