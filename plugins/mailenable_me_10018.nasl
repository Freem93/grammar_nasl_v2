#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(23754);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2011/04/20 01:55:04 $");

  script_bugtraq_id(21252);
  script_xref(name:"Secunia", value:"23047");

  script_name(english:"MailEnable IMAP Server Unspecified Buffer Overflow (ME-10018)");
  script_summary(english:"Checks version of MailEnable's MEIMAPS.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is prone to a buffer overflow attack." );
  script_set_attribute(attribute:"description", value:
"The IMAP server bundled with the version of MailEnable installed on
the remote host is affected by an unspecified denial of service and
potential buffer overflow vulnerability.  A remote attacker may be
able to exploit this issue to crash the affected service or to execute
arbitrary code with LOCAL SYSTEM privileges." );
  script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/hotfix/" );
  script_set_attribute(attribute:"solution", value:
"Apply Hotfix ME-10018." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2006/12/04");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/11/23");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mailenable:mailenable");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");
  script_dependencies("mailenable_detect.nasl");
  script_require_keys("SMB/MailEnable/Installed");
  script_require_ports(139, 445);
  exit(0);
}


include("misc_func.inc");


if (!get_kb_item("SMB/MailEnable/Installed")) exit(0);
if (get_kb_item("SMB/MailEnable/Standard")) prod = "Standard";
if (get_kb_item("SMB/MailEnable/Professional")) prod = "Professional";
else if (get_kb_item("SMB/MailEnable/Enterprise")) prod = "Enterprise";


# Check version of MEIMAPS.exe.
if (prod == "Professional" || prod == "Enterprise")
{
  kb_base = "SMB/MailEnable/" + prod;
  ver = read_version_in_kb(kb_base+"/MEIMAPS/Version");
  if (isnull(ver)) exit(0);

  # nb: file version for MEIMAPS.exe from ME-10018 is 1.0.0.25.
  if (
    ver[0] == 0 ||
    (ver[0] == 1 && ver[1] == 0 && ver[2] == 0 && ver[3] < 25)
  )
  {
    # Let's make sure the product's version number agrees with what's reportedly affected.
    # nb: MailEnable version numbers are screwy!
    ver2 = get_kb_item(kb_base+"/Version");
    if (isnull(ver2)) exit(0);

    if (
      # 1.6-1.82 Professional Edition
      # 2.0-2.32 Professional Edition
      (prod == "Professional" && ver2 =~ "^(1\.([67]($|[0-9.])|8$|8[0-2])|2\.([0-2]($|[0-9.])|3($|[012])))") ||
      # 1.1-1.30 Enterprise Edition
      # 2.0-2.32 Enterprise Edition
      (prod == "Enterprise" && ver2 =~ "^(1\.([12]($|[0-9].)|3$)|2\.([0-2]($|[0-9.])|3($|[012])))")
    ) security_hole(get_kb_item("SMB/transport"));
  }
}
