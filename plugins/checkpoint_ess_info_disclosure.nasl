#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52016);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/08/09 00:11:21 $");

  script_bugtraq_id(46224);
  script_osvdb_id(72797);
  script_xref(name:"Secunia", value:"43219");

  script_name(english:"Check Point Endpoint Security Server Information Disclosure");
  script_summary(english:"Looks for known private keys");

  script_set_attribute(attribute:"synopsis",value:
"The remote web server hosts an application that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description",value:
"Check Point Endpoint Security Server or Integrity Server appears to
be running on the remote system.  The installed version exposes
certain private directories, which contain sensitive information such
as SSL private keys, configuration files, and certain application
binaries.

An unauthenticated, remote attacker can leverage this issue to
download SSL private keys and perform Man-in-the-Middle (MITM) attacks
or launch other attacks based on the information obtained from the
configuration files.");

  script_set_attribute(attribute:"see_also", value:"http://www.rapid7.com/security-center/advisories/R7-0038.jsp");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2011/Feb/118");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d195fdf8");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate vendor patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_dependencies("http_version.nasl","apache_http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/apache");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

get_kb_item_or_exit('www/'+port+'/apache');

files = make_list("integrity-smartcenter.key", "integrity.key");

foreach file (files)
{
  url = "/conf/ssl/apache/"+file;
  res = http_send_recv3(port:port, method:"GET", item:url,exit_on_fail:TRUE);

  if(("-BEGIN RSA PRIVATE KEY-" >< res[2] && "-END RSA PRIVATE KEY-" >< res[2]) ||
     ("-BEGIN DSA PRIVATE KEY-" >< res[2] && "-END DSA PRIVATE KEY-" >< res[2])
    )
  {
    if(report_verbosity > 0)
    {
      report = get_vuln_report(items:url, port:port);

      if(report_verbosity > 1)
      report += '\n' +
        'Here are the contents of the private key file : \n\n'+
        crap(data:"-", length:30)+" snip "+crap(data:"-", length:30)+'\n'+
        res[2]+'\n'+
        crap(data:"-", length:30)+" snip "+crap(data:"-", length:30)+'\n';

      security_warning(port:port,extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}

exit(0, "The web server on port "+ port + " is not affected.");
