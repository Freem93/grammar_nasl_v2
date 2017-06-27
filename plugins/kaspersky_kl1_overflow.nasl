#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33094);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2008-1518");
  script_bugtraq_id(29544);
  script_osvdb_id(45958);
  script_xref(name:"Secunia", value:"30534");

  script_name(english:"Kaspersky Multiple Products kl1.sys Driver Local Overflow");
  script_summary(english:"Checks date of virus signatures");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is prone to a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of the Kaspersky product installed on the remote host
contains a stack-based overflow in its 'kl1.sys' kernel driver
involving its handling of IOCTL 0x800520e8.  A local attacker may be
able to leverage this issue to gain complete control of the affected
system." );
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=704
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?095ad6ba" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Jun/43" );
  # http://web.archive.org/web/20090323132253/http://www.kaspersky.com/technews?id=203038727
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f464377" );
 script_set_attribute(attribute:"solution", value:
"Update the virus signatures after 06/03/2008 and restart the computer." );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/05");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe",value:"cpe:/a:kaspersky_lab:kaspersky_anti-virus");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("kaspersky_installed.nasl");
  script_require_keys("Antivirus/Kaspersky/sigs");
  exit(0);
}

#

sigs = get_kb_item("Antivirus/Kaspersky/sigs");
if (sigs)
{
  sigs = split(sigs, sep:'/', keep:FALSE);
  if (
    sigs[0] == "unknown" ||
    int(sigs[2]) < 2008 || 
    (
      int(sigs[2]) == 2008 && 
      (
        int(sigs[0]) < 6 ||
        (int(sigs[0]) == 6 && int(sigs[1]) <= 3)
      )
    )
  )
  security_hole(get_kb_item("SMB/transport"));
}
