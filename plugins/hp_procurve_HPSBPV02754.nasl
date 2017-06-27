#
# (C) Tenable Network Security, Inc.
#
#

include("compat.inc");

if (description)
{
 script_id(69323);
 script_version("$Revision: 1.3 $");
 script_cvs_date("$Date: 2016/11/18 20:40:53 $");

 script_cve_id("CVE-2012-0133");
 script_bugtraq_id(52990);
 script_osvdb_id(81315);
 script_xref(name:"HP", value:"HPSBPV02754");
 script_xref(name:"IAVB", value:"2012-B-0044");
 script_xref(name:"HP", value:"SSRT100803");
 script_xref(name:"HP", value:"emr_na-c03249176");

 script_name(english:"HP ProCurve 5400 zl Switches Compact Flash Card Security Issue");
 script_summary(english:"Checks serial and model numbers to determine presence of flaw");

 script_set_attribute(attribute: "synopsis", value:"The remote host is missing a vendor-supplied software update.");
 script_set_attribute(attribute: "description", value:
"The remote HP ProCurve 5400 zl switch is missing a software update that
corrects an issue with a compact flash card that may contain
malware-infected content. 

Note that The J8726A Management Module in 5400 zl switches are only
affected if they possess the following serial numbers :

 - ID116AS04P through ID116AS0HR
 - ID117AS00H through ID126AS0FB");
 script_set_attribute(attribute: "solution", value:"Upgrade the software to version K.15.08.0007 or later.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03249176
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ec6db52");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:procurve_switch");

 script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/10");
 script_set_attribute(attribute:"patch_publication_date", value:"2012/04/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/13");

 script_set_attribute(attribute:"stig_severity", value:"II");
 script_end_attributes();


 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
 script_family(english:"Misc.");

 script_dependencies("ssh_get_info.nasl", "hp_procurve_version.nasl");
 script_require_keys("Host/HP_Switch");
 exit(0);
}

include("audit.inc");

function version_cmp(a, b)
{
 local_var i;

 a = split(a, sep:'.', keep:FALSE);
 b = split(b, sep:'.', keep:FALSE);

 for ( i = 0; i < max_index(a) ; i ++ )
 {
  if ( int(a[i]) < int(b[i]) )
        return -1;
  else if ( int(a[i]) > int(b[i]) )
        return 1;
 }
  return 0;
}

if ( ! get_kb_item('Host/HP_Switch') ) exit(0, "This is not an HP Switch.");

sn = get_kb_item("Host/HP_Switch/SerialNumber");
rev = get_kb_item("Host/HP_Switch/SoftwareRevision");
model = get_kb_item("Host/HP_Switch/Model");
if ( (!sn) || (!rev) || (!model) || (sn == "unknown") || (rev == "unknown") || (model == "unknown") )
  exit(0, "The Serial Number, Model Number, and/or Software version could not be obtained.");

flag = 0;

# Check affected Serial Numbers
serial_nums = make_list(
  "ID030AS0MZ",
  "ID034AS0QP",
  "ID049AS0D4",
  "ID051AS074",
  "ID104AS06S",
  "ID110AS0B6",
  "ID113AS0HH",
  "ID113AS0K2",
  "ID113AS0KM",
  "ID114AS00V",
  "ID114AS02F",
  "ID114AS03D",
  "ID114AS08N",
  "ID114AS0C8",
  "ID115AS08P",
  "ID115AS097",
  "ID115AS0BL");

foreach temp (serial_nums)
{
  if (temp == sn) flag++;
}

# check the affected models
products = make_list(
  "J9532A",
  "J9533A",
  "J9539A",
  "J9540A",
  "J9642A",
  "J9643A",
  "J8697A",
  "J8698A",
  "J8699A",
  "J8700A",
  "J9447A",
  "J9448A");


if (flag)
{
  flag = 0;
  foreach temp (products)
  {
    if (temp == model) flag++;
  }
}

# Check the Management Module model/serial number
# Vulnerable Model Number is:
#   J8726A
# Vulnerable serial numbers are:
#   ID116AS04P through ID116AS0HR
#   ID117AS00H through ID126AS0FB
if ( !flag )
{
  module_model = get_kb_item("Host/HP_Switch/show_modules");
  if (preg(pattern:"J8726A [^\r\n]* ID116AS0..", multiline:TRUE, string:module_model)) flag++;
}

# check software version
if (flag)
{
  flag = 0;
  rev_tmp = split(rev, sep:'.', keep:FALSE);
  if (rev_tmp[0] == "K")
    if (version_cmp(a:rev , b:"K.15.08.0007") < 0)
      flag++;
}

# report as needed
if (flag)
{
  report = string(
    "The Remote HP ProCurve system is not patched :\n",
    "  Model #: ", model, " with Serial #: ", sn, "\n",
    "\n",
    "    Current Software Revision : ", rev, "\n",
    "    Patched Software Revision : K.15.08.0007", "\n"
  );

  security_note(port:0, extra:report);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
