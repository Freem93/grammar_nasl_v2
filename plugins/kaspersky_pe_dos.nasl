#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(23997);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2007-0125");
  script_bugtraq_id(21901);
  script_osvdb_id(32588);

  script_name(english:"Kaspersky Anti-Virus PE File Handling DoS");
  script_summary(english:"Checks date of virus signatures");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an antivirus application that is
prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The version of Kaspersky Anti-Virus installed on the remote host is
affected by a denial of service issue that can be triggered with a
specially crafted PE (portable executable) file to send the scanning
engine into an infinite loop and prevent scanning of other files." );
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=459
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34269a05" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/456110/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Update the virus signatures to 01/02/2007 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/01/05");
 script_cvs_date("$Date: 2012/08/23 21:01:03 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe",value:"cpe:/a:kaspersky_lab:kaspersky_anti-virus");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");
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
    int(sigs[2]) < 2007 || 
    (int(sigs[2]) == 2007 && int(sigs[0]) == 1 && int(sigs[1]) <= 2)
  )
  security_warning(get_kb_item("SMB/transport"));
}

