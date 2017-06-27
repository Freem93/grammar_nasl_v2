#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31858);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2008-0308", "CVE-2008-0309");
  script_bugtraq_id(27911, 27913);
  script_osvdb_id(42331, 42332);

  script_name(english:"Symantec Decomposer Multiple Vulnerabilities (SYM08-006)");
  script_summary(english:"Checks for vulnerable versions of Symantec products"); 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote Symantec product is affected by multiple issues. 

By sending a specially crafted RAR file to TCP port 1344, an
unauthenticated attacker may be able to cause a denial of service
condition or execute arbitrary code, subject to privileges of the user
running the application." );
   # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=666  
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5b2e816" );
   # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=667
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d096172f" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/488827" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/488828" );
 script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2008.02.27.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to :

 - Symantec Scan Engine 5.1.6.31
 - Symantec AntiVirus Scan Engine 4.3.18.43
 - Symantec Mail Security for Microsoft Exchange 4.6.8.120/5.0.6.368" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119, 399);
 
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/14");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/02/26");
 script_cvs_date("$Date: 2016/12/14 20:33:27 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:scan_engine");
script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:symantec_antivirus_filtering_domino_mpe");
script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:symantec_antivirus_network_attached_storage");
script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:symantec_antivirus_scan_engine");
script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:symantec_antivirus_scan_engine_caching");
script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:symantec_antivirus_scan_engine_clearswift");
script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:symantec_antivirus_scan_engine_for_microsoft_sharepoint");
script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:symantec_antivirus_scan_engine_for_ms_isa");
script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:symantec_antivirus_scan_engine_messaging");
script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:symantec_mail_security_for_microsoft_exchange");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("symantec_scan_engine_installed.nasl","sms_for_msexchange.nasl");
  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");

port = kb_smb_transport();

# Check Symantec Antivirus Scan Engine Version

version = get_kb_item("Symantec/Symantec AntiVirus Scan Engine/Version");
if (version)
{
 v = split(version, sep:".", keep:FALSE);

 # Version 4.3.18.43 is not vulnerable.

 if (( int(v[0]) < 4  ) ||
     ( int(v[0]) == 4 && int(v[1]) < 3 ) ||
     ( int(v[0]) == 4 && int(v[1]) == 3 && int(v[2]) < 18 ) ||
     ( int(v[0]) == 4 && int(v[1]) == 3 && int(v[2]) == 18 &&  int(v[3]) < 43 )
   )
     {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Version ",version," of Symantec AntiVirus Scan Engine \n",
	  " is installed on the remote host.",
          "\n"
        );
        security_hole(port:port, extra:report);
       }  	
       else
   	 security_hole(port);
     }
}

# Check Symantec Scan Engine Version
# Version 5.1.6.31 is not vulnerable

version = get_kb_item("Symantec/Symantec Scan Engine/Version");
if (version)
{
 v = split(version, sep:".", keep:FALSE);
 if ( ( int(v[0]) < 5 ) ||
      ( int(v[0]) == 5 && int(v[1]) < 1 ) ||
      ( int(v[0]) == 5 && int(v[1]) == 1 && int(v[2]) < 6 ) ||
      ( int(v[0]) == 5 && int(v[1]) == 1 && int(v[2]) == 6 &&  int(v[3]) < 31 )
    )
   {
     if (report_verbosity)
      {
        report = string(
          "\n",
          "Version ",version," of Symantec Scan Engine is installed \n",
	  " on the remote host.",
          "\n"
        );
        security_hole(port:port, extra:report);
       }	
       else
    	security_hole(port);
    }
}

# Check for Symantec Mail Security for MS Exchange

version = get_kb_item("Symantec/SMSE/Version");
# Versions 5.0.6.368 and 4.6.8.120 are not vulnerable 

if (version)
{
 v = split(version, sep:".", keep:FALSE);
 if ( ( int(v[0]) <  4 ) ||
      ( int(v[0]) == 4 && int(v[1]) < 6 ) ||
      ( int(v[0]) == 4 && int(v[1]) == 6 && int(v[2]) < 8 ) ||
      ( int(v[0]) == 4 && int(v[1]) == 6 && int(v[2]) == 8 &&  int(v[3]) < 120 ) ||
      ( int(v[0]) == 5 && int(v[1]) == 0 && int(v[2]) < 6 ) ||
      ( int(v[0]) == 5 && int(v[1]) == 0 && int(v[2]) == 6 &&  int(v[3]) < 368) 
    )
   {
     if (report_verbosity)
      {
       report = string(
        "\n",
        "Version ",version," of Symantec Mail Security for MS Exchange\n",
        "is installed on the remote host.",
        "\n"
       );
        security_hole(port:port, extra:report);
       }
       else
        security_hole(port);
    }
}
