#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(57641);
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2016/12/01 21:21:53 $");

 script_name(english:"Unsupported IPSO Firewall");
 script_summary(english:"Checks cached initial page.");

 script_set_attribute(attribute:"synopsis", value:
"The remote firewall is no longer supported by its vendor.");
 script_set_attribute(attribute:"description", value:
"The remote host is a Check Point or Nokia IPSO firewall that is no
longer supported by its vendor.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
 # http://www.checkpoint.com/support-services/check-point-ipso-operating-system-support-timeline/
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7440cc2");
 script_set_attribute(attribute:"solution", value:"Upgrade to a firewall that is currently supported.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/25");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:nokia:ipso");

 script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");

 script_dependencies("os_fingerprint.nasl");
 script_require_ports("Host/OS", "Settings/PCI_DSS");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# See if we have a version from OS fingerprinting.
os = get_kb_item("Host/OS");
if (os && "Nokia IPSO Firewall " >< os)
{
  match = eregmatch(string:os, pattern:'IPSO Firewall ([0-9\\.]+([\\(0-9\\)]+)?(-BUILD.+)?)');
  if (match)
  {
    version = match[1];

    # http://en.wikipedia.org/wiki/Nokia_IPSO
    if (version =~ '^(([0-57]([^0-9]|$)|6(-|\\.[0-1]([^0-9]|$)|$)))')
    {
      register_unsupported_product(product_name:"Nokia IPSO Firewall", cpe_class:CPE_CLASS_OS,
                                   cpe_base:"nokia:ipso", version:version);

      if (report_verbosity > 0)
      {
        report = '\n  Installed IPSO version : ' + version + '\n';
        security_hole(port:0, extra:report);
      }
      else security_hole(port:0);
      exit(0);
    }
    else exit(0, "IPSO version "+version+" is currently supported.");
  }
}

# nb: if we get here, OS fingerprinting didn't work or didn't give us a version.
if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

ports = get_kb_list("Services/www");
if ( ! isnull(ports) )
{
 foreach port ( make_list(ports) )
 {
   page = get_kb_item("Cache/" + port + "/URL_/");
   if ( ! page ) page = http_get_cache(port:port, item:"/");
   if ( page && '<form METHOD="POST" NAME="form" ACTION="/cgi-bin/home.tcl">' >< page &&
	        '<b>Acquire Exclusive Configuration Lock</b>' >< page )
   {
    register_unsupported_product(product_name:"Nokia IPSO Firewall", cpe_class:CPE_CLASS_OS,
                                 cpe_base:"nokia:ipso");
    security_hole(0);
    exit(0);
   }
 }
}

exit(0, "The device does not appear to be an IPSO firewall.");
