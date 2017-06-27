#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(20386);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/05/04 14:21:28 $");

  script_cve_id("CVE-2005-3357");
  script_bugtraq_id(16152);
  script_osvdb_id(22261);

  script_name(english:"Apache mod_ssl ssl_hook_Access Error Handling DoS");
  script_summary(english:"Checks for error document denial of service vulnerability in Apache mod_ssl.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache running on the remote host is affected by a
denial of service vulnerability due to a flaw in mod_ssl that occurs
when it is configured with an SSL vhost with access control and a
custom 400 error page. A remote attacker can exploit this, via a
non-SSL request to an SSL port, to cause a NULL pointer to be
dereferenced, resulting in crashing individual child processes or even
the entire server.");
  script_set_attribute(attribute:"see_also", value:"http://issues.apache.org/bugzilla/show_bug.cgi?id=37791" );
  # https://web.archive.org/web/20060515051822/http://httpd.apache.org/security/vulnerabilities_20.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08a97b5b" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.0.58 or later. Alternatively, update the
Apache configuration to use 'SSLRequire' whenever 'SSLCipherSuite' is
used.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");

port = get_http_port(default:443);

# Make sure this is Apache.
get_kb_item_or_exit('www/'+port+'/apache');

# Check if we could get a version first
# As we are not using the version solely to flag the issue, we will
# not worry about whether or not the install is backported
version = get_kb_item_or_exit('www/apache/'+port+'/version', exit_code:1);
source = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);

# Check if the version looks like either ServerTokens Major/Minor was used.
if (version =~ '^2(\\.0)?$')
  audit(AUDIT_VER_NOT_GRANULAR, "Apache", port, source);

# Affects 2.0 < 2.0.58
if (version !~ '^2\\.0') audit(AUDIT_WRONG_WEB_SERVER, port, "Apache 2.0.x");

# Check banner for mod_ssl
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (isnull(banner))
    audit(AUDIT_WEB_BANNER_NOT, port);
  if ("mod_ssl" >!< banner)
    audit(AUDIT_WRONG_WEB_SERVER, port, "Apache with mod_ssl");
}

# Check version and if within our valid range, test for the vulnerability
# https://web.archive.org/web/20080117030426/http://httpd.apache.org/security/vulnerabilities_20.html
if (ver_compare(ver:version, fix:"2.0.58") == -1)
{
  # If it's using SSL....
  encaps = get_kb_item("Transports/TCP/"+port);
  if (! encaps)
    exit(0, "Undefined SSL level on port "+port+".");

  if (encaps < 2)
    exit(0, "The web server on port "+port+" is in cleartext.");

  req = http_get(item:"/", port:port);
  # Try several times to connect w/o SSL.
  tries = 5;
  for (iter = 0; iter < tries; iter++)
  {
    soc = open_sock_tcp(port, transport:ENCAPS_IP);
    if (soc)
    {
      send(socket:soc, data:req);
      res = recv(socket:soc, length:1024);
      close(soc);
      # It's *not* a problem if we got a response.
      if (res) exit(0, "The Apache server on port "+port+" answered and is not affected.");
    }
  }

  # There's a problem since we didn't get a response after several attempts.
  #
  # nb: this exploit won't crash the entire web server unless the remote
  #     Apache is configured to use the non-default worker MPM.
  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to verify this issue by sending a non-SSL request to'+
      '\nthe SSL port. The failure of the web server to respond to the request'+
      '\ndemonstrates that the web server is affected by this vulnerability.'+
      '\nNote that this can trigger a DoS condition when using the non-default'+
      '\nworker Multi-Processing Module.\n'+
      '\nYou may verify this by reviewing the Apache logs and checking for'+
      '\nsegmentation fault entries in the error log. This will depend on how'+
      '\nthe web server logs were configured, and review of Apaches official'+
      '\ndocumentation is recommended.\n';
     security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, version);
