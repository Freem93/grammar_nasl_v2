#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76348);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/09/12 18:47:28 $");

  script_cve_id("CVE-2013-5680");
  script_bugtraq_id(62729);
  script_osvdb_id(97932);
  script_xref(name:"EDB-ID", value:"28683");

  script_name(english:"HylaFAX+ 5.2.4 < 5.5.4 Remote Buffer Overflow");
  script_summary(english:"Checks the version of HylaFAX+.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a
heap-based remote buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the HylaFAX+ install hosted on the
remote web server is 5.2.4 or later and prior to 5.5.4. It is,
therefore, affected by a heap-based remote buffer overflow
vulnerability.

The flaw exists when 'hfaxd' is compiled with support for LDAP. The
user input for LDAP authentication is not properly validated. This
could allow a remote attacker to cause a denial of service or execute
arbitrary code.

Note that Nessus has not tested for this issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://hylafax.sourceforge.net/news/5.5.4.php");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Sep/148");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 5.5.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hylafax:hylafax");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("hylafax_detect.nbin");
  script_require_keys("hylafax/installed", "hylafax/version", "Settings/ParanoidReport");
  script_require_ports("Services/hylafax", 4559);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"hylafax", default:4559, exit_on_fail:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

banner = get_kb_item_or_exit("hylafax/banner");
version = get_kb_item_or_exit("hylafax/version");

fixed = '5.5.4';

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] == 5 &&
  (
    ver[1] == 2 ||
    ver[1] == 3 ||
    ver[1] == 4 ||
    (ver[1] == 5 && ver[2] < 4)
  )
)
{
 if (report_verbosity > 0)
  {
    report =
      '\n  Source            : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "HylaFAX+", port, version);
