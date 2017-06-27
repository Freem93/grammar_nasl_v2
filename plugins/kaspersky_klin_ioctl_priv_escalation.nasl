#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(23996);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2006-4926");
  script_bugtraq_id(20635);
  script_osvdb_id(29891);

  script_name(english:"Kaspersky Labs Anti-Virus IOCTL Local Privilege Escalation");
  script_summary(english:"Checks date of virus signatures");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is prone to a
local privilege escalation issue." );
 script_set_attribute(attribute:"description", value:
"The version of Kaspersky Anti-Virus installed on the remote host allows
a local attacker to execute arbitrary code with kernel privileges by
passing a specially crafted Irp structure to an IOCTL handler used by
the KLIN and KLICK device drivers.  By leveraging this flaw, a local
attacker may be able to gain complete control of the affected system." );
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=425
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?010a6f57" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/449258/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/449301/30/0/threaded" );
  # http://web.archive.org/web/20071030114411/http://www.kaspersky.com/technews?id=203038678
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c69e5f92" );
 script_set_attribute(attribute:"solution", value:
"Update the virus signatures after 10/12/2006 and restart the computer." );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/10/19");
 script_cvs_date("$Date: 2016/05/16 14:02:52 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/10/20");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe",value:"cpe:/a:kaspersky_lab:kaspersky_anti-virus");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("kaspersky_installed.nasl");
  script_require_keys("Antivirus/Kaspersky/sigs");

  exit(0);
}


sigs = get_kb_item("Antivirus/Kaspersky/sigs");
if (sigs)
{
  sigs = split(sigs, sep:'/', keep:FALSE);
  if (
    sigs[0] == "unknown" ||
    int(sigs[2]) < 2006 || 
    (
      int(sigs[2]) == 2006 && 
      (
        int(sigs[0]) < 10 ||
        (int(sigs[0]) == 10 && int(sigs[1]) <= 12)
      )
    )
  )
  security_hole(get_kb_item("SMB/transport"));
}
