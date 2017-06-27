#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73339);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/09/12 23:24:20 $");

  script_cve_id("CVE-2014-0011");
  script_bugtraq_id(66313);
  script_osvdb_id(104672);

  script_name(english:"TigerVNC < 1.3.1 ZRLE Heap-based Buffer Overflow");
  script_summary(english:"Checks version of TigerVNC");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a VNC application that is affected by a
heap-based buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-identified version number, the TigerVNC install
hosted on the remote web server is affected by a heap-based buffer
overflow vulnerability.

A flaw exists when performing bounds check during ZRLE decoding. This
could allow a remote attacker with a malicious server and a specially
crafted request to execute arbitrary code.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/p/tigervnc/mailman/message/32120476/");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tigervnc:tigervnc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("tigervnc_java_viewer_detect.nbin");
  script_require_ports("Services/www", 5800);
  script_require_keys("Host/TigerVNC_Java_Viewer", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "Host/TigerVNC_Java_Viewer";
port = get_kb_item_or_exit(kb_base+"/Port");
version = get_kb_item_or_exit(kb_base+"/Version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixed = '1.3.1';

# Versions < 1.3.1 are vulnerable
if (ver_compare(ver:version, fix:fixed, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, "TigerVNC", version);
