#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71536);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_cve_id("CVE-2013-6051");
  script_bugtraq_id(63937);
  script_osvdb_id(100446);

  script_name(english:"Quagga 0.99.21 bgp_attr.c BGP Update DoS");
  script_summary(english:"Checks the version of Quagga");

  script_set_attribute(attribute:"synopsis", value:
"The remote service may be affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Quagga's BGP daemon listening on the remote host is affected by a denial
of service vulnerability.  This issue exists due to a failure to
properly initialize the packet's total size variable in the 'bgp_attr.c'
source file.  Normal, valid BGP update messages can trigger this
issue.");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 0.99.22 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"see_also", value:"https://savannah.nongnu.org/forum/forum.php?forum_id=7501");
  # http://savannah.spinellicreations.com//quagga/quagga-0.99.22.changelog.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11e41901");
  # http://git.savannah.gnu.org/gitweb/?p=quagga.git;a=commitdiff;h=8794e8d229dc9fe29ea31424883433d4880ef408
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4828438");
  script_set_attribute(attribute:"see_also", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=730513");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:quagga:quagga");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("quagga_zebra_detect.nasl");
  script_require_keys("Quagga/Installed", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "Quagga Zebra";
kb = "Quagga/";

port = get_kb_item_or_exit(kb + "Installed");

kb += port + "/";
banner = get_kb_item_or_exit(kb + "Banner");
ver = get_kb_item_or_exit(kb + "Version");

if (ver !~ "^\d+(\.\d+)*$") audit(AUDIT_NONNUMERIC_VER, app, port, ver);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (ver == "0.99.21")
{
  fix = "0.99.22";

  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port, ver);
