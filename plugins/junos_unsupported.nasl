#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55933);
  script_version("$Revision: 1.29 $");
  script_cvs_date("$Date: 2017/01/27 20:54:05 $");

  script_name(english:"Juniper Junos Unsupported Version Detection");
  script_summary(english:"Checks for EOL and extended support.");

  script_set_attribute(attribute:"synopsis", value:
"The operating system running on the remote host is no longer
supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
the Juniper Junos operating system running on the remote host is no
longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.juniper.net/support/eol/junos.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Juniper Junos that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("datetime.inc");

# Parse version
version = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item('Host/Juniper/model');

match = eregmatch(string:version, pattern:'^([0-9.]+(X[0-9]+)?)([^0-9]|$)');
if (isnull(match)) exit(1, 'Error parsing version: ' + version);
release = match[1];

eoe_date = NULL;
eos_date = NULL;

##############################
# End of Engineering (EOE)
#  Extended support contract needed beyond this date
eoe = make_array(
  "16.2",    "2019-11-29",
  "16.1",    "2019-07-28",
  "15.1X49", "2019-12-01",
  "15.1",    "2018-06-04",
  "14.2",    "2017-11-05",
  "14.1X53", "2018-12-31",
  "14.1",    "2017-12-13",
  "13.3",    "2017-01-22",
  "13.2X52", "2016-12-31",
  "13.2X51",  "2015-12-31",
  "13.2X50",  "2014-06-28",
  "13.2",     "2015-08-29",
  "13.1X50",  "2015-06-30",
  "13.1",     "2015-03-15",
  "12.3X54",  "2018-01-18",
  "12.3X52",  "2015-08-23",
  "12.3X51",  "2015-03-15",
  "12.3X50",  "2016-01-31",
  "12.3X48",  "2020-06-30",
  "12.3",     "2016-01-31",
  "12.2X50",  "2015-01-31",
  "12.2",     "2014-09-05",
  "12.1X49",  "2014-04-19",
  "12.1X48",  "2014-12-30",
  "12.1X47",  "2016-08-18",
  "12.1X46",  "2016-12-30",
  "12.1X45",  "2014-07-17",
  "12.1X44",  "2016-01-18",
  "12.1", "2014-03-28",
  "11.4", "2014-12-21",
  "11.3", "2012-07-15",
  "11.2", "2012-06-15",
  "11.1", "2011-11-15",
  "10.4", "2013-12-08",
  "10.3", "2011-08-03",
  "10.2", "2011-05-15",
  "10.1", "2010-11-15",
  "10.0", "2012-11-15",
  "9.6",  "2010-05-06",
  "9.5",  "2010-02-15",
  "9.4",  "2009-11-11",
  "9.3",  "2011-11-15",
  "9.2",  "2009-05-12",
  "9.1",  "2009-01-28",
  "9.0",  "2008-11-15",
  "8.5",  "2010-11-16",
  "8.4",  "2008-05-09",
  "8.3",  "2008-01-18",
  "8.2",  "2007-11-15",
  "8.1", "2009-11-06",
  "8.0", "2007-05-15",
  "7.6", "2007-02-15",
  "7.5", "2006-11-08",
  "7.4", "2006-08-15",
  "7.3", "2006-05-16",
  "7.2", "2006-02-14",
  "7.1", "2005-11-14",
  "7.0", "2005-08-15",
  "6.4", "2005-05-12",
  "6.3", "2005-02-15",
  "6.2", "2004-11-15",
  "6.1", "2004-08-15",
  "6.0", "2004-05-15",
  "5.7", "2004-02-15",
  "5.6", "2003-11-15",
  "5.5", "2003-08-15",
  "5.4", "2003-05-15",
  "5.3", "2003-02-15",
  "5.2", "2002-11-12",
  "5.1", "2002-08-12",
  "5.0", "2002-05-15",
  "4.4", "2002-02-12",
  "4.3", "2001-11-12",
  "4.2", "2001-08-13",
  "4.1", "2001-05-14",
  "4.0", "2001-02-12"
);


##############################
# End of Support (EOS)
#  Extended support end date
eos = make_array(
  "16.2",    "2020-05-29",
  "16.1",    "2020-01-28",
  "15.1X49", "2020-05-01",
  "15.1",    "2018-12-04",
  "14.2",    "2018-05-05",
  "14.1X53", "2019-06-30",
  "14.1",    "2018-06-13",
  "13.3",    "2017-07-22",
  "13.2X52", "2017-06-30",
  "13.2X51", "2016-06-30",
  "13.2X50", "2014-12-28",
  "13.2",    "2016-02-29",
  "13.1X50", "2015-12-30",
  "13.1",    "2015-09-15",
  "12.3X54", "2018-07-18",
  "12.3X52", "2016-02-23",
  "12.3X51", "2015-09-15",
  "12.3X50", "2016-07-31",
  "12.3X48", "2022-06-30",
  "12.3",    "2016-07-31",
  "12.2X50", "2015-07-31",
  "12.2",    "2015-03-05",
  "12.1X49", "2014-10-19",
  "12.1X48", "2015-06-30",
  "12.1X47", "2017-02-18",
  "12.1X46", "2017-06-30",
  "12.1X45", "2015-01-17",
  "12.1X44", "2016-07-18",
  "12.1", "2014-09-28",
  "11.4", "2015-06-21",
  "11.3", "2013-03-15",
  "11.2", "2013-02-15",
  "11.1", "2012-05-15",
  "10.4", "2014-06-08",
  "10.3", "2011-12-21",
  "10.2", "2011-11-15",
  "10.1", "2011-05-15",
  "10.0", "2013-05-15",
  "9.6", "2010-11-06",
  "9.5", "2010-08-15",
  "9.4", "2010-05-11",
  "9.3", "2012-05-15",
  "9.2", "2009-11-12",
  "9.1", "2009-07-28",
  "9.0", "2009-05-15",
  "8.5", "2011-05-16",
  "8.4", "2008-11-09",
  "8.3", "2008-07-18",
  "8.2", "2008-05-15",
  "8.1", "2010-05-06",
  "8.0", "2007-11-15",
  "7.6", "2007-08-15",
  "7.5", "2007-05-08",
  "7.4", "2007-02-15",
  "7.3", "2006-11-16",
  "7.2", "2006-08-14",
  "7.1", "2006-05-14",
  "7.0", "2006-02-15",
  "6.4", "2005-11-12",
  "6.3", "2005-08-15",
  "6.2", "2005-05-15",
  "6.1", "2005-02-15",
  "6.0", "2004-11-15",
  "5.7", "2004-08-15",
  "5.6", "2004-05-15",
  "5.5", "2004-02-15",
  "5.4", "2003-11-15",
  "5.3", "2003-08-15",
  "5.2", "2003-05-15",
  "5.1", "2003-02-15",
  "5.0", "2002-11-15",
  "4.4", "2002-08-15",
  "4.3", "2002-05-15",
  "4.2", "2002-02-15",
  "4.1", "2001-11-15",
  "4.0", "2001-08-15"
);

#Determine EOE Date
#  12.3 & 12.3X50 extended EOE/EOS
if (release == "12.3" || release == "12.3X50")
{
  if (model)
  {
    if (
        model =~ "^EX-?[0-9]+" ||
        model =~ "^QFX-?[0-9]+"
       )
      eoe_date = "2017-01-31";
      eos_date = "2017-07-31";
  }
}

#  12.1X46 extended EOE/EOS
if (release == "12.1X46")
{
  if (model)
  {
    if (model =~ "^J[0-9]+")
    {
      eoe_date = '2018-07-31';
      eos_date = '2018-07-31';
    }
    else if (
      model == 'SRX100B'      ||
      model == 'SRX100H'      ||
      model == 'SRX110H-VA'   ||
      model == 'SRX110H-VB'   ||
      model == 'SRX210BE'     ||
      model == 'SRX210HE'     ||
      model == 'SRX210HE-POE' ||
      model == 'SRX220H'      ||
      model == 'SRX220H-POE'  ||
      model == 'SRX240B'      ||
      model == 'SRX240B2'     ||
      model == 'SRX240H'      ||
      model == 'SRX240H-POE'  ||
      model == 'SRX240H-DC'   ||
      model == 'LN1000-V'     ||
      model == 'LN1000-CC'
    )
    {
      eoe_date = '2019-05-10';
      eos_date = '2019-05-10';
    }
  }
}

#  15.1 extended EOE/EOS
else if (release == "15.1")
{
  if (model)
  {
    if (
        model =~ "^M[0-9]+" ||
        model == "EX4500"   ||
        model == "EX6200"   ||
        model == "EX6210"   ||
        model == "EX8200"   ||
        model == "QFX3500"  ||
        model == "QFX3600"  ||
        model == "T640"     ||
        model == "T1600"
        )
      eoe_date = "2019-05-01";
      eos_date = "2021-05-01";
  }
}

if (!eoe_date)
  eoe_date = eoe[release];

#Determine EOS Date
if (!eos_date)
  eos_date = eos[release];

# Check the EOE date
if (eoe_date)
{
  date = split(eoe_date, sep:"-");
  if (unixtime() < mktime(year:date[0], mon:date[1], mday:date[2]))
  {
    if(model)
      exit(0, "JunOS "+release+" is still supported on model "+model+".");
    else 
      exit(0, "JunOS "+release+" is still supported.");
  }
}

#Check EOS date
if (eos_date)
{
  set_kb_item(
    name:"Host/Juniper/JUNOS/extended_support",
    value:"Junos "+release+" extended support ends on " + eos_date + "."
    );
}
# Couldn't identify either the EOE or EOS
if (!eoe_date && release !~ "^[0-3]\.")
  exit(0, "The EOE date could not be determined.");

# Anything left is affected
if (!eos_date)
  eos_date = "Unknown";
if (!eoe_date)
  eoe_date = "Unknown";
set_kb_item(name:"Host/Juniper/JUNOS/unsupported", value:TRUE);

register_unsupported_product(product_name:'Juniper Junos', cpe_class:CPE_CLASS_OS,
                             version:tolower(release), cpe_base:"juniper:junos");

report =
  '\n  Installed version            : ' + version  +
  '\n  Junos release                : ' + release  +
  '\n  End of life date             : ' + eoe_date +
  '\n  End of extended support date : ' + eos_date +
  '\n  EOE and EOS URL              : http://www.juniper.net/support/eol/junos.html' +
  '\n';
security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
