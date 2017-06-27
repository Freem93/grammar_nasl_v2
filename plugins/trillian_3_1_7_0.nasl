#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25757);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2007-3832", "CVE-2007-3833");
  script_bugtraq_id(24927);
  script_osvdb_id(38170, 38171);
  script_xref(name:"CERT", value:"786920");

  script_name(english:"Trillian aim:// URI Handler Vulnerabilities");
  script_summary(english:"Checks version number of Trillian");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an instant messaging application that is
affected by two vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Trillian installed on the remote host contains a buffer
overflow in its AIM protocol URI handler in 'aim.dll' and also allows
creation of arbitrary files with arbitrary content using specially-
crafted 'aim://'' URIs.  A remote attacker may be able to leverage
these issues to execute arbitrary code as the current user." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f055f2d5" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Jul/297" );
 script_set_attribute(attribute:"see_also", value:"http://blog.ceruleanstudios.com/?p=170" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Trillian 3.1.7.0 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/07/18");
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
if (ver && ver =~ "^([0-2]\.|3\.(0\.|1\.[0-6]\.))")
  security_hole(get_kb_item("SMB/transport"));
