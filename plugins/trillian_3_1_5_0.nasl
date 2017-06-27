#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25120);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2007-2478", "CVE-2007-2479");
  script_bugtraq_id(23730);
  script_osvdb_id(35721, 35722);

  script_name(english:"Trillian < 3.1.5.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Trillian");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an instant messaging application that is
susceptible to multiple issues." );
 script_set_attribute(attribute:"description", value:
"The version of Trillian installed on the remote host reportedly
contains several buffer overflow issues involving its handling of
UTF-8 characters.  A remote attacker may be able to leverage these
issues to execute arbitrary code as the current user." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59b1efb6" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/May/12" );
 script_set_attribute(attribute:"see_also", value:"http://blog.ceruleanstudios.com/?p=131" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Trillian 3.1.5.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/01");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:trillian:trillian");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("trillian_installed.nasl");
  script_require_keys("SMB/Trillian/Version");

  exit(0);
}


ver = get_kb_item("SMB/Trillian/Version");
if (ver && ver =~ "^([0-2]\.|3\.(0\.|1\.([0-4]\.|5\.0)))")
  security_hole(get_kb_item("SMB/transport"));
