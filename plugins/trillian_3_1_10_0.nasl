#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(32400);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2008-2407", "CVE-2008-2408", "CVE-2008-2409");
  script_bugtraq_id(29330);
  script_osvdb_id(45681, 45682, 45683);
  script_xref(name:"Secunia", value:"30336");

  script_name(english:"Trillian < 3.1.10.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Trillian");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an instant messaging application that is
affected by several vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Trillian installed on the remote host reportedly
contains several vulnerabilities :

  - A stack-based buffer overflow in 'aim.dll' triggered
    when parsing messages with overly long attribute values
    within the 'FONT' tag.

  - A memory corruption issue within XML parsing in
    'talk.dll' triggered when processing malformed
    attributes within an 'IMG' tag.

  - A stack-based buffer overflow in the header-parsing code
    for the MSN protocol when processing the
    'X-MMS-IM-FORMAT' header.

Successful exploitation of each issue can result in code execution
subject to the privileges of the current user." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-029" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-030" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-031" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/May/552" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/May/553" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/May/554" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Trillian 3.1.10.0 or later as it is reported to resolve
these issues." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/05/22");
 script_cvs_date("$Date: 2016/11/03 20:40:07 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:trillian:trillian");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("trillian_installed.nasl");
  script_require_keys("SMB/Trillian/Version");

  exit(0);
}


include("global_settings.inc");


ver = get_kb_item("SMB/Trillian/Version");
if (ver && ver =~ "^([0-2]\.|3\.(0\.|1\.[0-9]\.))")
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Trillian version ", ver, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
