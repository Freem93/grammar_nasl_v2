#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70761);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/11 13:40:21 $");

  script_cve_id("CVE-2013-2236");
  script_bugtraq_id(60955);
  script_osvdb_id(94839);

  script_name(english:"Quagga < 0.99.22.2 OSPF API Buffer Overflow");
  script_summary(english:"Check the version of Quagga");

  script_set_attribute(attribute:"synopsis", value:
"The remote service may be affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Quagga listening on the remote host is potentially affected by a
stack-based buffer overflow that occurs in the OSPF API server
('ospf_api.c') when it receives an LSA larger than 1488 bytes. 

The vulnerability is only present when Quagga is compiled with the
'--enable-opaque-lsa' flag and the OSPF API server is running (ospfd is
run with the '-a' parameter).  Exploitation of this issue may lead to a
denial of service or arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://lists.quagga.net/pipermail/quagga-dev/2013-July/010622.html");
  # http://git.savannah.gnu.org/gitweb/?p=quagga.git;a=commitdiff;h=3f872fe60463a931c5c766dbf8c36870c0023e88
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9cfd7251");
  script_set_attribute(attribute:"see_also", value:"http://nongnu.askapache.com//quagga/quagga-0.99.22.3.changelog.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 0.99.22.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/05");

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

fix = "0.99.22.2";
if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0) audit(AUDIT_LISTEN_NOT_VULN, app, port, ver);

fullver = get_kb_item(kb + "FullVersion");
if (isnull(fullver)) fullver = ver;

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + fullver +
    '\n  Fixed version     : ' + fix +
    '\n';
}
security_warning(port:port, extra:report);
