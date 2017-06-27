#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81785);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 21:08:40 $");

  script_name(english:"IBM Rational ClearQuest Unsupported");
  script_summary(english:"Checks for unsupported versions of IBM Rational Clearquest.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is no longer
supported.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM Rational ClearQuest
on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # http://www-01.ibm.com/software/support/lifecycleapp/PLCSearch.wss?q=rational+clearquest
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a07098c4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a supported version of Rational ClearQuest.

Alternatively, contact IBM to acquire an enhanced support contract.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_clearquest");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("ibm_rational_clearquest_installed.nasl", "ibm_rational_clearquest_web_client_detect.nbin");
  script_require_keys("installed_sw/IBM Rational ClearQuest");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = 'IBM Rational ClearQuest';
install = get_single_install(app_name:appname, combined:TRUE, exit_if_unknown_ver:TRUE);

version = install['version'];
path    = install['path'];

port    = install['port'];
if (!isnull(port))
  path = build_url(port:port, qs:install['path']);
else
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
}

eos_dates = make_array(
  "^7\.1($|[^0-9])",     "2014/09/30",
  "^7\.0($|[^0-9])",     "2011/09/30",
  "^2003\.06($|[^0-9])", "2008/09/30",
  "^2002\.05($|[^0-9])", "2005/09/30",
  "^2001\.04($|[^0-9])", "2005/09/30"
);

eos_url  = "http://www.nessus.org/u?a07098c4";
eos_date = NULL;

# Enhanced support (3 years after EOL)
ext_dates = make_array(
  "^7\.1($|[^0-9])",     "2017/09/30"
);

# ignore extended support dates when report paranoia is set to 'Paranoid'
note = "";
if (report_paranoia < 2)
  foreach v (keys(ext_dates))
  {
    if (version =~ v)
    {
      set_kb_item(
        name:"www/"+port+"/"+appname+"/extended_support",
        value:appname + " support ends on " + ext_dates[v]
      );
      exit(0, appname + " may be on enhanced support.");
    }
  }
else
  note = '\n' + 'Note that Nessus has not checked if '+ appname +' is on enhanced support.';


foreach ver_regex (keys(eos_dates))
{
  if (version !~ ver_regex) continue;
  eos_date = eos_dates[ver_regex];
  break;
}

if (isnull(eos_date))
  exit(0, "The " + appname + " install at " + path + " is still supported.");

register_unsupported_product(
  product_name : appname,
  cpe_base     : "ibm:rational_clearquest",
  version      : version
);

if (report_verbosity > 0)
{
  latest = "8.0.0.x / 8.0.1.x";  

  report =
    '\n  Product             : ' + appname  +
    '\n  URL                 : ' + url      +
    '\n  Installed version   : ' + version  +
    '\n  End of support date : ' + eos_date +
    '\n  End of support URL  : ' + eos_url  +
    '\n  Latest version      : ' + latest   + 
    '\n';
  if (note) report += note; 
  security_hole(port:port, extra:report);
}
else security_hole(port);
