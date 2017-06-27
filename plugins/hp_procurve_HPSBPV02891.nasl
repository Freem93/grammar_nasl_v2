#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69346);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id("CVE-2008-7270");
  script_bugtraq_id(45254);
  script_osvdb_id(69655);
  script_xref(name:"HP", value:"HPSBPV02891");
  script_xref(name:"HP", value:"SSRT101113");
  script_xref(name:"HP", value:"emr_na-c03819065");

  script_name(english:"HP ProCurve Switches Remote Unauthorized Information Disclosure");
  script_summary(english:"Checks model number and software version to determine presence of flaw");

  script_set_attribute(attribute: "synopsis", value:"The remote host is missing a vendor-supplied software update.");
  script_set_attribute(attribute: "description", value:
"The remote HP ProCurve switch is missing a software update that
corrects an issue where an attacker could remotely cause an unauthorized
information disclosure.");
  script_set_attribute(attribute: "solution", value:"Upgrade to the appropriate software version or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03819065
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c5c3056");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:procurve_switch");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("hp_procurve_version.nasl");
  script_require_keys("Host/HP_Switch");
  exit(0);
}

include("audit.inc");

# ###########################
# function assumes both a and b are of the form K.15.12
# ###########################
function version_cmp(a, b)
{
 local_var i, vala, valb, max;

 a = split(a, sep:'.', keep:FALSE);
 b = split(b, sep:'.', keep:FALSE);

 # check that the first string part matches
 if (toupper(a[0]) != toupper(b[0])) return -2;

 max = max_index(a);
 if (max_index(b) > max) max = max_index(b);

 # now loop over all of the remaining int parts
 for ( i = 1; i < max ; i ++ )
 {
  if (i >= max_index(a)) vala = 0;
  else vala = int(a[i]);
  if (i >= max_index(b)) valb = 0;
  else valb = int(b[i]);

  if ( vala < valb )
        return -1;
  else if ( vala > valb )
        return 1;
 }
  return 0;
}

if ( ! get_kb_item('Host/HP_Switch') ) exit(0, "This is not an HP Switch.");

rev = get_kb_item("Host/HP_Switch/SoftwareRevision");
model = get_kb_item("Host/HP_Switch/Model");
if ( (!rev) || (!model) || (rev == "unknown") || (model == "unknown") )
  exit(0, "The model number and/or software version could not be obtained.");

flag = 0;
patched_ver = "";

# A.14.20 or A.15.06
if ( (model == "J9565A") ||
     (model == "J9562A") )
{
  if (version_cmp(a:"A.14.20", b:rev) > 0)
  {
    patched_ver = "A.14.20 or A.15.06";
    flag++;
  }
  if ( (version_cmp(a:"A.15.0", b:rev) <= 0) && (version_cmp(a:"A.15.06", b:rev) > 0) )
  {
    patched_ver = "A.15.06";
    flag++;
  }
}

# E.11.34
if ( (model == "J4850A") ||
     (model == "J8166A") ||
     (model == "J4819A") ||
     (model == "J8167A") ||
     (model == "J4849A") ||
     (model == "J4849B") ||
     (model == "J4848A") ||
     (model == "J4848B") )
  if (version_cmp(a:"E.11.34", b:rev) > 0)
  {
    patched_ver = "E.11.34";
    flag++;
  }

# H.10.108
if ( (model == "J8762A") ||
     (model == "J4900A") ||
     (model == "J4900B") ||
     (model == "J4900C") ||
     (model == "J4899A") ||
     (model == "J4899B") ||
     (model == "J4899C") ||
     (model == "J8164A") ||
     (model == "J8165A") )
  if (version_cmp(a:"H.10.108", b:rev) > 0)
  {
    patched_ver = "H.10.108";
    flag++;
  }

# i.10.98
if ( (model == "J4903A") ||
     (model == "J4904A") )
  if (version_cmp(a:"i.10.98", b:rev) > 0)
  {
    patched_ver = "i.10.98";
    flag++;
  }

# J.14.61 or J.15.06
if ( (model == "J9299A") ||
     (model == "J9298A") )
{
  if (version_cmp(a:"J.14.61", b:rev) > 0)
  {
    patched_ver = "J.14.61 or J.15.06";
    flag++;
  }
  if ( (version_cmp(a:"J.15.0", b:rev) <= 0) && (version_cmp(a:"J.15.06", b:rev) > 0) )
  {
    patched_ver = "J.15.06";
    flag++;
  }
}

# L.11.38
if ( (model == "J8772B") ||
     (model == "J8770A") ||
     (model == "J9064A") ||
     (model == "J8773A") ||
     (model == "J9030A") ||
     (model == "J8775B") ||
     (model == "J8771A") ||
     (model == "J8772A") ||
     (model == "J8774A") ||
     (model == "J8775A") )
  if (version_cmp(a:"L.11.38", b:rev) > 0)
  {
    patched_ver = "L.11.38";
    flag++;
  }

# M.10.95
if ( (model == "J4906A") ||
     (model == "J4905A") )
  if (version_cmp(a:"M.10.95", b:rev) > 0)
  {
    patched_ver = "M.10.95";
    flag++;
  }

# N.11.56
if ( (model == "J9021A") ||
     (model == "J9022A") )
  if (version_cmp(a:"N.11.56", b:rev) > 0)
  {
    patched_ver = "N.11.56";
    flag++;
  }

# Q.11.55
if ( (model == "J9019B") ||
     (model == "J9019A") )
  if (version_cmp(a:"Q.11.55", b:rev) > 0)
  {
    patched_ver = "Q.11.55";
    flag++;
  }

# R.11.92
if ( (model == "J9085A") ||
     (model == "J9087A") ||
     (model == "J9086A") ||
     (model == "J9088A") ||
     (model == "J9089A") )
  if (version_cmp(a:"R.11.92", b:rev) > 0)
  {
    patched_ver = "R.11.92";
    flag++;
  }

# S.14.36 or S.15.06
if ( (model == "J9138A") ||
     (model == "J9137A") )
{
  if (version_cmp(a:"S.14.36", b:rev) > 0)
  {
    patched_ver = "S.14.36 or S.15.06";
    flag++;
  }
  if ( (version_cmp(a:"S.15.0", b:rev) <= 0) && (version_cmp(a:"S.15.06", b:rev) > 0) )
  {
    patched_ver = "S.15.06";
    flag++;
  }
}

# U.11.43
if (model == "J9020A")
  if (version_cmp(a:"U.11.43", b:rev) > 0)
  {
    patched_ver = "U.11.43";
    flag++;
  }

# Y.11.38
if ( (model == "J9279A") ||
     (model == "J9280A") )
  if (version_cmp(a:"Y.11.38", b:rev) > 0)
  {
    patched_ver = "Y.11.38";
    flag++;
  }

# report as needed
if (flag)
{
  report = string(
    "The Remote HP ProCurve system is not patched :\n",
    "  Model # : ", model, "\n",
    "\n",
    "    Current Software Revision : ", rev, "\n",
    "    Patched Software Revision : ", patched_ver, "\n"
  );

  security_warning(port:0, extra:report);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
