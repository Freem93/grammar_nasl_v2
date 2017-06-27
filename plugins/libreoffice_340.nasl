#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55574);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2012/05/18 01:11:03 $");

  script_cve_id("CVE-2011-2685");
  script_bugtraq_id(48387);
  script_osvdb_id(73314);
  script_xref(name:"CERT", value:"953183");

  script_name(english:"LibreOffice < 3.3.3 / 3.4.0 LWP File Handling Overflow");
  script_summary(english:"Checks version of LibreOffice");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has a program affected by a buffer
overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of LibreOffice installed on the remote host is earlier
than 3.3.3 / 3.4.0.  As such, it is reportedly affected by a stack
buffer overflow in the Lotus Word Pro import filter that arises from
its failure to properly handle object ids in '.lwp' documents. 

If an attacker can trick a user on the affected system into importing
a specially crafted .lwp document into the application, he could
leverage this issue to execute arbitrary code subject to the user's
privileges."
  );
  # http://cgit.freedesktop.org/libreoffice/filters/commit/?id=d93fa011d713100775cd3ac88c468b6830d48877
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?49efef93"
  );
  # http://cgit.freedesktop.org/libreoffice/filters/commit/?id=278831e37a23e9e2e29ca811c3a5398b7c67464d
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?87ef8ac0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to LibreOffice 3.3.3 / 3.4.0 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");

  script_dependencies("libreoffice_installed.nasl");
  script_require_keys("SMB/LibreOffice/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

kb_base = "SMB/LibreOffice";

version = get_kb_item_or_exit(kb_base+"/Version");
path = get_kb_item_or_exit(kb_base+"/Path");
version_ui = get_kb_item_or_exit(kb_base+"/Version_UI");

if (
  (version =~ "^3\.3\." &&
   ver_compare(ver:version, fix:'3.3.301.500', strict:FALSE) == -1)
  ||
  (version =~ "^3\.4\." &&
   ver_compare(ver:version, fix:'3.4.12.500', strict:FALSE) == -1)
)
{
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path + 
      '\n  Installed version : ' + version_ui + 
      '\n  Fixed version     : 3.3.3 / 3.4.0\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The LibreOffice "+version_ui+" install under "+path+" is not affected.");
