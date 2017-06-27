#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63135);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_name(english:"McAfee WebShield SMTP Unsupported");
  script_summary(english:"Checks the remote banner");

  script_set_attribute(attribute:'synopsis', value:"The remote mail service is unsupported.");
  script_set_attribute(attribute:'description', value:
"The install of McAfee WebShield SMTP listening on the remote host is
no longer supported since the product reached End of Life on March 31,
2010.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:'solution', value:"Migrate to another mail filtering application.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:'see_also', value:"https://kc.mcafee.com/corporate/index?page=content&id=KB61078");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:webshield");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  script_family(english:"SMTP problems");

  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");


port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0, "The SMTP server listening on port "+port+" is broken.");

banner = get_smtp_banner(port:port, exit_on_fail:TRUE);
if (" WebShield SMTP" >!< banner) exit(0, "The banner from the SMTP server listening on port "+port+" is not from McAfee WebShield SMTP.");

register_unsupported_product(product_name:"McAfee WebShield",
                             cpe_base:"mcafee:webshield");

if (report_verbosity > 0)
{
  report = '\n  Banner           : ' + chomp(banner) +
           '\n  End-of-life date : 2010/03/31' +
           '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
