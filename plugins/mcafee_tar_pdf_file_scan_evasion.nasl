#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42290);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_bugtraq_id(36848); 
  script_osvdb_id(59356);
  script_xref(name:"Secunia", value:"37179");
  script_xref(name:"MCAFEE-SB", value:"SB10003");

  script_name(english:"McAfee Antivirus TAR / PDF Scan Evasion (SB10003)");
  script_summary(english:"Checks the DAT version.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application installed on the remote host is affected by a
scan evasion vulnerability.");
  script_set_attribute(attribute:"description", value:
"The McAfee antivirus application installed on the remote host is
affected by a scan evasion vulnerability due to the virus definitions
being out of date. In this case, the DAT file version of the installed
antivirus product is prior to 5693. An attacker can exploit this, by
embedding malicious code in a specially crafted TAR or PDF file, to
evade detection by the scanning engine.");
  script_set_attribute(attribute:"see_also", value:"http://www.g-sec.lu/mcafee-pdf-bypass.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2009/Oct/273");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10003");
  script_set_attribute(attribute:"solution", value:
"Update the McAfee DAT file to version 5693 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:virusscan_plus");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:mcafee:total_protection");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:internet_security_suite");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:virusscan_usb");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:virusscan_enterprise");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:virusscan_commandline");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:securityshield_for_microsoft_isa_server");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:securityshield_for_microsoft_sharepoint");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:securityshield_for_email_servers");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:email_gateway");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:total_protection_for_endpoint");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:active_virus_defense");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:active_virusscan");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:linuxshield");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:groupshield");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:netshield");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:portalshield");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:virex");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_installed.nasl");
  script_require_keys("Antivirus/McAfee/installed","Antivirus/McAfee/dat_version");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");

dat = get_kb_item("Antivirus/McAfee/dat_version");
if (!dat) exit(1, "The 'Antivirus/McAfee/dat_version' KB item is missing.");

if (dat > 0 && dat < 5693)
{
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "DAT file version ", dat, " is installed on the remote system.\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
