#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70144);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/02 14:37:09 $");

  script_cve_id("CVE-2009-1566");
  script_bugtraq_id(37183);
  script_osvdb_id(60585);
  script_xref(name:"Secunia", value:"36069");
  script_xref(name:"IAVA", value:"2009-A-0133");

  script_name(english:"Roxio Creator 9.x <= 9.0.136 Image Handling Integer Overflow");
  script_summary(english:"Checks version of Creator9.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by an
integer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Roxio Creator install on the remote host
is 9.x earlier than or equal to 9.0.136.  It is, therefore, affected by
an integer overflow vulnerability related to image handling that could
allow arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2009/Dec/9");
  script_set_attribute(attribute:"solution", value:"Upgrade to Roxio Creator 2010 SP1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:roxio:creator");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:roxio:easy_media_creator");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_dependencies("roxio_creator_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/roxio_creator/Installed");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "Roxio Creator";
kb_base = "SMB/roxio_creator/";

path = get_kb_item_or_exit(kb_base + "Path");
ver  = get_kb_item_or_exit(kb_base + "Version");

vuln_cut_off = "9.0.136";
if (ver_compare(ver:ver, fix:vuln_cut_off, strict:FALSE) < 1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : Creator 2010 SP1' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port:port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname);
