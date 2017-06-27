#TRUSTED 60b8e6ba646fd8fd952d1ae3bdc3c328c19a419a0ad6fa5aff902d8fcac5bdaa7898a04f54f6a8c6b3a5009f355e08d873b511267fef6c0ae5094e0ed34869361a07f9d94594135fa904ac12674797ffada3093a8a7fe68925f2e58a8e0fa9dc388b805a644aa3c4891d2943a2c5bb2d7884434496b86c41b3a0f6988807446000f6e85243fb9b8c5d810e021b01759ce65f9e7625a42df7eea88f22138bd18773630d62a3db80fd44ec3d345562dc6f843be782feb2e41ffe5a828f9e2dd8a98d484ee5c54aa3ee610fd5601b0b22ff254232ad5fc3dad18322af094c30206db2ad41df670052426a9089cbe2c28156472a22ea8eb16e7c7c2b2c2cc0af6e650f75f523d8664587a8ef6708c0ebd62481570730a015d66d30be0c3e862ffeea6cb896d291a88287a211a614b458fe49d8600196f65b42f6cf8e35601bd836cd9ecb2bd728ad1a65d284242c29adf92b89aa205cb9d7cd978ba91954ef9d40e17d38a7a125e12783b190bfd18745d30ab4d4ecaacc4c2af173c4392d542e5b1d85b4e42ebc6e714888cdff4afbe05526e4212451f115273ea15930aa24c6ea13ff1b919498e9edae4fbc60b86985da51e2a1b6d56d315911bb14cbac72025f61c41ea584088997373ab0c84efe6437c53222abce15cd0fe537e8a5648ae6e43c3347f2a6ddb2f9738a24a422c226f3780cc5ddf8ad8b20c6380f3027b320305c
#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 5200) exit(0);

include("compat.inc");

if (description)
{
  script_id(72582);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/10/08");

  script_name(english:"Unsupported Cisco Operating System");
  script_summary(english:"Check if the operating system is still maintained.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an obsolete operating system.");
  script_set_attribute(attribute:"description", value:
"According to its version, the remote Cisco operating system is
obsolete and is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"solution", value:"Upgrade to a version that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencie("os_fingerprint.nasl");
  script_require_keys("Host/OS");

  exit(0);
}

include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");
#include("misc_func.inc");

# #####################################
# get current date
# #####################################
global_var DATE;

now = localtime(utc:1);
DATE = now['year'] + ".";
if (now['mon'] < 10) DATE += "0";
DATE += now['mon'] + ".";
if (now['mday'] < 10) DATE += "0";
DATE += now['mday'];

# #####################################
# Functions
# #####################################
function regexify(str)
{
  return ereg_replace(pattern:"([^A-Za-z0-9])", replace:"\\1", string:str);
}

function report_and_exit(txt)
{
  local_var line, match, pat, tag_name, tmp_ver;

  security_hole(port: 0, extra: '\n' + txt);
  set_kb_item(name: 'Host/OS/obsolete', value: TRUE);
  set_kb_item(name: 'Host/OS/obsolete/text', value:txt);

  tag_name = "";
  if ("NX-OS" >< txt) tag_name = "cisco:nx-os";
  else if ("IOS-XE" >< txt) tag_name = "cisco:ios_xe";
  else if ("IOS-XR" >< txt) tag_name = "cisco:ios_xr";
  else if ("IOS" >< txt) tag_name = "cisco:ios";
  else if ("PIX" >< txt) tag_name = "cisco:pix_firewall_software";

  if (tag_name)
  {
    tmp_ver = NULL;
    pat = "(IOS|IOS-XE|IOS-XR|NX-OS|PIX) ([^ ]+)( has)? reached end";
    line = egrep(pattern:pat, string:txt);
    if (line)
    {
      match = eregmatch(pattern:pat, string:line);
      if (!isnull(match)) tmp_ver = tolower(match[2]);
    }
    register_unsupported_product(product_name:"Cisco", cpe_class:CPE_CLASS_OS,
                                 cpe_base:tag_name, version:tmp_ver);
  }
  exit(0);
}

function checkDate(date, url, os, version)
{
  local_var report;
  report = "";

  # Compare dates
  #  as the dates are stored as YYY.MM.DD, we can use a generic
  #  version compare function to compare them

  # check to see if the current date is <= the End of Life date
  if ((date == "") || (ver_compare(ver:date, fix:DATE) <= 0))
  {
    if (date == "")
      report = os + " " + version + " has reached end of support.";
    else
      report = os + " " + version + " reached end of support on " + ereg_replace(pattern:"\.", replace:"-", string:date);
    report += '\n';
    if (url != "")
    {
      report += "For more information, see : " + url;
      report += '\n';
      report += '\n';
    }
    report_and_exit(txt:report);
  }
}

function exact_check(eol_list, ostype, url)
{
  local_var os, eol_date, parts, entry;
  os = "";
  eol_date = "";

  # test for null/empty list
  if (!eol_list || isnull(eol_list)) return 0;

  # loop over all entries (should really only be one entry)
  foreach entry (split(eol_list, keep:FALSE))
  {
#    entry = ereg_replace(pattern:"\\n$", replace:"", string:entry);

    parts = split(entry, sep:",", keep:FALSE);
    if (!isnull(parts))
    {
      if ((eol_date == "") || (ver_compare(ver:parts[4], fix:eol_date) > 0))
      {
        os = parts[1];
        eol_date = parts[4];
      }
    }
  }
  if (os != "")
    checkDate(date:eol_date, url:url, os:ostype, version:os);
}

function regex_check(ostype, version, model, eol_list, url)
{
  local_var entry, report, regex, part, parts;

  # test for null/empty list
  if (!eol_list || isnull(eol_list)) return 0;

  # loop over all entries (should really only be one entry)
  foreach entry (split(eol_list, keep:FALSE))
  {
    parts = split(entry, sep:",", keep:FALSE);
    if (!isnull(parts))
    {
      if ((parts[0] == "1") || (parts[0] == "2"))
      {
        # "2"
        regex = parts[1];

        # "1"
        if (parts[0] == "1")
        {
          part = split(parts[1], sep:'_', keep:0);
          regex = part[0] + "(([^0-9].*[\.|\)]" + part[1] + "($|[0-9]))|(\.?" + part[1] + "($|[0-9])))";
        }

        # check the OS version
        if (version =~ regex)
        {
          # are we comparing model versions?
          if (parts[2] != "")
          {
            # compare hardware models if possible
            if ((!isnull(model)) && (model != "") && (model =~ parts[2]))
            {
              # check to see if the current date is <= the End of Life date
              checkDate(date:parts[4], url:url, os:ostype, version:version);
            }
          }
          else
          {
            # check to see if the current date is <= the End of Life date
            checkDate(date:parts[4], url:url, os:ostype, version:version);
          }
        }
      }
    }
  }
}

# #####################################
# Determine OS type
# #####################################
os = get_kb_item("Host/OS");
conf = get_kb_item("Host/OS/Confidence");
if (conf <= 70) exit(0, "The OS fingerprinting confidence level is too low.");
if ( os && '\n' >< os ) exit(0, "The OS fingerprint is too fuzzy.");

# #####################################
# parse OS to determine OS type/version and obtain model
# #####################################
os_type = "";
os_ver = "";
model = NULL;

if (ver = eregmatch(string:os, pattern:"Cisco NX-OS Version\s+([0-9a-zA-Z\.\(\)]+)[^\s\r\n]*"))
{
  os_type = "NX-OS";
  os_ver = ver[1];
  model = get_kb_item("Host/Cisco/NX-OS/Model");
}
else if (ver = eregmatch(string:os, pattern:"Cisco IOS XE\s+([0-9a-zA-Z\.\(\)]+)[^\s\r\n]*"))
{
  os_type = "IOS-XE";
  os_ver = ver[1];
  model = NULL;
  if (get_kb_item("Host/local_checks_enabled"))
  {
    # this advisory only addresses CISCO ASR 1000 series
    buf = cisco_command_kb_item("Host/Cisco/Config/show_platform", "show platform");
    if (buf)
    {
      match = eregmatch(pattern:"Chassis type:\s+ASR([^ ]+)", string:buf);
      if (!isnull(match)) model = match[1];
    }
  }
}
else if (ver = eregmatch(string:os, pattern:"Cisco IOS XR\s+([0-9a-zA-Z\.\(\)]+)[^\s\r\n]*"))
{
  os_type = "IOS-XR";
  os_ver = ver[1];
  model = NULL;
}
else if (ver = eregmatch(string:os, pattern:"CISCO IOS\s+([0-9a-zA-Z\.\(\)]+)[^\s\r\n]*"))
{
  os_type = "IOS";
  os_ver = ver[1];
  model = get_kb_item("Host/Cisco/IOS/Image");
}
else if (ver = eregmatch(string:os, pattern:"CISCO PIX\s+([0-9a-zA-Z\.\(\)]+)[^\s\r\n]*"))
{
  os_type = "PIX";
  os_ver = ver[1];
  model = NULL;
}

if ((os_type == "") || (os_ver == "")) exit(0, "The remote system is not currently supported by this plugin.");

i = 0;
oses = make_array();
urls = make_array();
data = make_array();

oses[i] = "IOS";
urls[i] = "";
data[i] = "QlpoMzFBWSZTWY1YpAUAAB6fgAR3fGAgAAAfAAEABCAAUKNGQNGmRoFVT9SQ9Gpkek9NTWhbe1s12wQto5ipUvi86jrsiE2+FMkp63lMFZfT9fyWK6dzJqTkwfxdyRThQkI1YpAU";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/iosswrel/ps8802/ps1828/prod_end-of-life_notice0900aecd80295938.html";
data[i] = "QlpoMzFBWSZTWcKxCrcAAASfAAAFfGAgAAAEAAEgACGptEzQEDQNC3P0Ea1AyWEU8McAcXk7wu5IpwoSGFYhVuA=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/iosswrel/ps8802/ps1828/prod_end-of-life_notice0900aecd80563fea.html";
data[i] = "QlpoMzFBWSZTWSWfV0MAAA8fgAR3fGAgAAAfAAEABCAAVFGjIGjTI0GqemifqJibUzKLIxOnEOMFue6YM9RUKEWVouLCffWyn2vC7xdOd+LuSKcKEgSz6uhg";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/iosswrel/ps8802/ps6948/ps1833/prod_end-of-life_notice0900aecd8052e0f5.html";
data[i] = "QlpoMzFBWSZTWcM1PK8AAAcfAAAFeoACAAAFgAEgADEA0ADU9Q9TaTDMJwxOwxNmuafwegg3FJTgu5IpwoSGGanleA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/iosswrel/ps8802/ps6948/ps5013/ps1761/prod_end-of-life_notice0900aecd801ef222.html";
data[i] = "QlpoMzFBWSZTWbwbD4QAAAefAAAFcsAKAAAFgAEgADEAAAaIxPQIVL+gimkNI3mdShDIozTkPXxdyRThQkLwbD4Q";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/iosswrel/ps8802/ps6969/ps1835/prod_end-of-life_notice09186a0080091852.html";
data[i] = "QlpoMzFBWSZTWbzFjr4AAAgbAAAFfEAQRYABIAAhpMQ8kyEAAA6O+NScEELLiWoKBD3inj++LuSKcKEheYsdfA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/iosswrel/ps8802/ps6969/ps5012/prod_end-of-life_notice0900aecd8011131b.html";
data[i] = "QlpoMzFBWSZTWfWRDFcAAAefAAAFfCAQAAAFgAEgACEqaGjyTQgGgBRsS6OBDLo8yiNY4Wsyn8XckU4UJD1kQxXA";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/iosswrel/ps8802/ps6970/ps1838/prod_end-of-life_notice0900aecd804be5cf.html";
data[i] = "QlpoMzFBWSZTWYb9BdUAAAYbAAAFcQAIBYABIAAhplNoTCAaaaKLZpKyL2VkfPowEKdsM5wu5IpwoSEN+guq";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/iosswrel/ps8802/ps6970/ps6017/end_of_life_c51-568765.html";
data[i] = "QlpoMzFBWSZTWUX49QYAAAmbAAAHe6AIT4ABIAAxTJiZBkYNU9MhPQ1P1MoWjFg/HNtkMOZSpUQG2gQrm4Iqp7iuh1n8XckU4UJBF+PUGA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/customer/products/hw/switches/ps298/prod_eol_notice09186a008009239e.html";
data[i] = "QlpoMzFBWSZTWTW67D4AAAefAAAFcqAkAAAFgAEgADEAAAamajJ6TJ1p5E0gQghluaDhGAwvDcx74u5IpwoSBrddh8A=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/customer/products/hw/switches/ps298/prod_eol_notice09186a00800923a4.html";
data[i] = "QlpoMzFBWSZTWfxAz5UAAAkfAAAFfEAkAAAFgAEgACGmoZPRMhAAARh0CqkTIJbNXQW2F4rh6+LuSKcKEh+IGfKg";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/customer/products/hw/switches/ps298/prod_eol_notice09186a00800923a5.html";
data[i] = "QlpoMzFBWSZTWb9PZusAAAWfAAAFeCAkAAAFgAEgACGpvVGmJkIBoAhneAVEZxSrZTtOG5ReFdy/i7kinChIX6ezdYA=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/customer/products/sw/iosswrel/prod_category_end_of_life.html";
data[i] = "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";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/customer/products/sw/iosswrel/ps1828/prod_eol_notice09186a008032d3e2.html";
data[i] = "QlpoMzFBWSZTWQkPv4UAAAebAAAFeAAEBYABIAAhKmmanoQgGmmj0UOGwY52ZMrxZCRt0lnxdyRThQkAkPv4UA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/customer/products/sw/iosswrel/ps1831/prod_eol_notice09186a008032d55c.html";
data[i] = "QlpoMzFBWSZTWaj7aDIAAA8fgAR3dSAgAAAfAAEABCAAVFA00MjJiCVT9RNPUPU002mpWnM72hM4+L4j40w2RIqvZcoWCOFnHRq89rrfF3JFOFCQqPtoMg==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/customer/products/sw/iosswrel/ps5012/prod_eol_notice09186a008032d54a.html";
data[i] = "QlpoMzFBWSZTWRZc8l4AAAefAAAFdyAQAAAFgAEgACGpkaaeQhAAALTEkhIJBsvYoJ4cNrJvrn4u5IpwoSAsueS8";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/iosswrel/ps8802/ps10587/ps10592/end_of_life_c51-632352.html";
data[i] = "QlpoMzFBWSZTWVGEyOkAAiwbgABnf2AEBD4r33BAAkTgCiGlR/5VQGmgDEZABp+pSpoBoA9EANDGTE0wmmJgJpgCkqmptKmn4oj1PRMR6jTTTKkqTCpKk1VJUmipKk4OzbYqqqqqqqqqqqgAAAAAAAKqQ1q5Jkn7CEITeltltltltlkADJJcjw2TZML9XKmkwurKmkwvHR0zjLbpx026ZxnoesRzEfmI0RxEePEOgeA8B6V8ojiI9k9ojVaI9Yj9A+ER2Ue0RwHrEcxH8RH1iPER+qcg5iMDmIwcKOU8xGiNSl90X0hzDBgwYMGDDDiI/uO8j71PnHv/u222212iOseYj3B9j6R7qn9A5H/K0fBXAPmD0B5iOq6UfhG7qBytIBbcAtuAW3A3ZEd4j8RHeOtV2j0WVjnGxsbXyV+TvHNF2juc3Rra2tnmdjabTabHWl3PjVdT4n7q8g1U29AAAGTrk5ZJkn+LuSKcKEgowmR0gA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/iosswrel/ps8802/ps10587/ps10592/end_of_life_c51-657926.html";
data[i] = "QlpoMzFBWSZTWaKi3F4AB+8fgABnf+AAAgAEPivfcFAFXQd0HCQFEXtLUZqJpo//aqpGQ0ZMjRgEqnvVSaGCMmBNMhkCU/UqVDUeoAGIAPUE1KlM1JtNKe1RkaGj1GmgVT1VI08o0BkZAAOpByQfwQcEHUg8dPTt69/b8vfxVVVVqAAAAAKqqqqqqAAAAAAAAAAAAAAAAAAAB5ZDwAAAAAAAAHnjGWMYx0vWSJJJJJJJJL01raSIFHCJZRFEURRFEURRkJIgAAAq7sIAAO7r3/JfJcZ/W1EXi4zzaivFGebUF4qzzeedZFlxnm1EXi4zzaiLxcZ5tRF4uM82oi8XGebUReLjPNqOLxcZ5xxW6Tz1VyQdiD8EHsQdCDz8Rd/KLjiVx4U8C5F6C8C7C8C7RfsQfMg7FeZBiuxB0IOaXYgyq+hB7C799sAAAAAAFXcAAAF3TugkAAnx7oPJD9SD5EHuQfmQc3pS5lOSDQuSDC5IMLoQwuKXcg4FiDQvITC4IMlWIML7BLC+ouRYWFisVlMphYWFhYWFhYWFhYWFhYXJB/cXrRPtRX7xfH+622trayIiIAAAD07ru7vfd163sQfCh/JfWL4lVf0+mbWzZs2bNmzZtRXyi/4llV3JeUJ0hPcusJ7kHNVcRMX3nXfD1B7bBQG2Cg2wcBtoigNsFAbYKA2wUBtgoDbBQG2GW223HHG210IO5B9yDvF1kZozGuY2g2ZjEaVFSViqpBQUFBQUJRXfh3XXtmNzMaGGNQa5jozYiWSJEiRIkSJEu3MaFKxSkR0cdEdEdEdEdEdbW02t1KnqL3lTqXuXzJe0Ll3XfR3Tuvz/IQAABAG222xdi/BB/4u5IpwoSFFRbi8A";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/iosswrel/ps8802/ps10587/ps10592/end_of_life_notice_c51-695183.html";
data[i] = "QlpoMzFBWSZTWT3e44kAAKAbgABnf+AEBD4r3RAwASwSESp6QjIAAADGExMmAmAAClKQZQaNAADTERO6JiiXom7Tflna1qqqqqqqqqiJchzvXDMMxZoc5OknOTwk1k26prN0695yk3SeEm+TjNZMnKTfJ3SesmknOThO2Txk0msmOEmJySbSeUmiT4h5zjMmTJkzMmThJtGkm0nwHtHI/Z0mp0m4NgfgXg+kSBgH5POLIyMkhSJkie0SyGAYJbCSQifkvQLkuzhISMoWx8x/TYsOJ0k/xdyRThQkD3e44kA=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/iosswrel/ps8802/ps10587/ps10592/end_of_life_notice_c51-717651.html";
data[i] = "QlpoMzFBWSZTWSrmFzgABS0fgABnf2AAAgAEPivfcFAEHQ3S5IKJVUGpqg//VVBpoA0AAEqfoqpowIwACMQSeqlKep6gBpo9QGgBNSqSeyQ1MppgAjT1DGTE0wmmJgJpg4CXiEvsEuwS4CXr18vPnv7+OOAAAAAAAAAAAAAAAAAAAAAAAAAAABlta1pafJUqVKlSpUqVKlSpRYTe2kraStpK2kraStpKgRUAK1dAAG28O67quPLnTpriKRAjZbgiKRAjZbgiKRAjZbgiKRAjZbgiKRAjZbgjhTirjpzp01zt1iIiMfLba1222tewS7hLuEu/opyp6KdVOqnKnFT4BLqEvmEvIqwS8Vbz7bWu3YAAAAVqAALZsABOmreG21rrtta/sJe8JeYS4jxjmU5CWU4CWU5CXxCXRT5hLKcEWU6x6BLopglpTwKukEvxA+inZTKZTKZTKZTKZTKZTKZTwCX6jsivvqt3tvL9oiIiAADtsS6xzHoEv2RfY+sfsi/L6Zs2bNmzZU7R/1GS70eFJe6kvU60l6hLhLpJY/hVx5bbb26dIigOc5EUBznIigOc5EUBznIigOc5EaA506W1te4Jdwl/Al3jqDmOx11rlbK7AoCgKAoGrbbWrbar4Uex5xyI7Jdjh0lJSUlJSUnu27aMWMTZtNm02bTZsbN1RXml6huu3v28a29ta0ta9Gzb6+IAAAA29W3+22tf8XckU4UJAq5hc4A=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/iosswrel/ps8802/ps10587/ps11746/end_of_life_notice_c51-706108.html";
data[i] = "QlpoMzFBWSZTWYbu8xcAAHMbgABne+AEBD4r3RAwAPgDGAAmAAJhjAATAAEwb1RQEamnqBo00aepoNR2GozG/PO7u7u7u7uSSpG7rUlUlW3HA3HIbDXkmiXJsLFjBPQUnoOgoajqOQwGScxSZjceoyG0HsKg7SPdMUpKSkpMBlFjQdpHzHR4cNHDBJik8Mkn4KZuHfRVSVUwHMfoxjNmxzqpUnDKRa9qlUrBJq7x/NUlM3A/xdyRThQkIbu8xcA=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/iosswrel/ps8802/ps1829/end_of_life_notice_c51-697971.html";
data[i] = "QlpoMzFBWSZTWQnF9PoAARIbgABnf+AIJDgrUBAwAXlEqCqn6pUfpQafqjQNGjFGhoAAAAqKjUR7SmaQDJpyQeiDug0QckHvtrc7+3TbGMY68ds7Zuc5znGMYxnOfnKDwQZQZQeUFQZYHG/PefFlrhtt4a0000023vln5YHNgbt0FVBqg6a22qjsguqD9QaOEFScEF52oNEF0VBzQWQaW1BhBWjmg+EH0g8BrVSZYM5qSqkH24SSSVJJJJJJJJJJJJb+EGEHDVBlB3QbIOqCoOrA6sD/YHP9qqVVJVVVVq3hB/IPKD/F3JFOFCQCcX0+gA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/iosswrel/ps8802/ps6947/ps5187/prod_end-of-life_notice0900aecd8052e110.html";
data[i] = "QlpoMzFBWSZTWcml4ccAAA4fgAR3eqAgAAAfAAEABCAAUKNGQNGmRoNU81TTJpgMUK1juTJO97ayahnI0JgqI58EMgoTnibz7h3iyYb8XckU4UJDJpeHHA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/iosswrel/ps8802/ps6947/ps5207/prod_bulletin0900aecd803a0ffe.html";
data[i] = "QlpoMzFBWSZTWYiZ6soAAAgbAAAFeYAEBYABIAAxANAA1PU0yeieoipRItBIB1HrETzQfcp58XckU4UJCImerKA=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/iosswrel/ps8802/ps6968/ps6441/end_of_life_notice_c51-545733.html";
data[i] = "QlpoMzFBWSZTWW8TDJQACT+bgABnf+AEBD4r3zBQBhBsBMd4FRBySVMVpVP0n/tCqhMAAAEab1VUAAAAADMlVMkwQYDQR6TCaqj1RPSNAAABoFKU1E9MqekyAA00acsmSTM5N5+o3QAABbQBWgAAC2g3JmFG6AAALaADdAAAFtADAAAAtoAAAABbQAAAbbbbZXbbKqqqqqqCqSycrmszNauZrMzWnmazM1rr6H0z/xJJJdQTbbbfX0WSSSCS4OXLjjjjkCSSSAu2227bJJJAABJJJAXbbbdtkkkgAAkkkgLtttu2ySSQAASSSQF2223bZJJIAAJJJIC7bbbtskkkAAEkkkBdttt22SSRJJJQLtttu2ySSQAASSSQF2223bZJJJxmazM1q2WW3qmPP5NdXGugONdAca6A411caTVxpoDjXQHGugONdAcaJWolaiVrMStYlaiVqJWsxK1iVqJWolaiVqJWolaiVrMStRK0laxK1iVrErWY1zTLGuaYxrmmboq3kK5EK2JRyQnbpG2htqttRpNo0MRpNJtGhpNJqNDSajUaGo1Go0NRqNRobRtGwyjuneOqd08E7x4DndN03TdN43jeNx27DtGcxtHEcRxHEcRxHjHI25HA4HA4HA4G9eVKjeriQrRWEK4EK8CFc5Cc3XJmGYZhmGYZlmGYTMGDEXaQrcQrYhXoQrvKrelcxCvEqtUrYhWEK+6skrgQr6KtCFbUVlK4kJ4UqOxRpJdCllDmlRopbSr2iWJdaVGI6gZHpEuoG0bUPvI4kYRhGRkZGRkjJGSMkYRhGUMoZQyhiWJZGRkZHaltk4WyT3sll58wAAAAAAAAAAAAAAAAAAAAAALZJwtlsdB5UqPVQ/VD+UPQodShih81D2UPdSo6UPpQ+XbfNtsVVUVUVVVUVVVVVVVVVVVVVVVVVVVVVVVXhDqpJxSo9aVHoNyh+RtS6UPwPah1iXvUPGhlD4KGrZJy49gKqqgCqqqoAAAAGZmZmZmZmZmZHJQ4oedDzUP9Uk/d4kChQoQhYFChQgQIQkCBCEgQIECBAhCBAAAAh121ciFf4u5IpwoSDeJhkoA=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/iosswrel/ps8802/ps6969/ps1835/ps4032/prod_end-of-life_notice0900aecd80330813.html";
data[i] = "QlpoMzFBWSZTWa/K43cAAA8fgAR3eSAgAAAfAAEABCAAVFA00MjJiDU9UzJNNNlNpqV6xNkg3Zcu7OI5cbHam1aTkIlCIU7fDcM+HTfF3JFOFCQr8rjdwA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/iosswrel/ps8802/ps6969/ps5012/ps4293/prod_bulletin09186a00800c9473.html";
data[i] = "QlpoMzFBWSZTWW5Ap40AAA8fAAAFfAAEAABFgAEgAFQlTTEYAVVPUxH6SaSdtEerUIWcbPmULKZdYb4qxTx0o0XckU4UJBuQKeNA";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/iosswrel/ps8802/ps6970/ps1838/end_of_life_notice_c51-462739.html";
data[i] = "QlpoMzFBWSZTWToJescAAGIfgABnf+AQAAgEGCtAEDAA2GigAADJkEeVQ0GgAaAb1SQaTap6NQaPKXRwj+RsjVHNt9cVXxx59Y5ujZFIujtFkZI0RpjGemKrbGMb8I2nyjwixG6KxPaK7RU5RV0VNUeUZIvnsjpGUMrosj6R+ItnVXRVkUXRVIp7iHclVVVVVVVZECQXkHhBkQYEOkdIsjtH+LuSKcKEgdBL1jg=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/iosswrel/ps8802/ps6970/ps6017/end_of_life_c51-568765.html";
data[i] = "QlpoMzFBWSZTWfiHWbYABOKfgABnf+ABAAhEvitdkFAEfRHi8DBFsNhB7JTf+qqP35VUAANABhgmBMBDRk0wEnqpKmQGhoAYgAmqqekp/oqeMpAMjQG9UCkqU1NH6oaNMRoDCGsUt4pfmKW0UsxS+GO2fr43408uzHkAB091WpXKwBw4UvQ61rOtYd991qtU5XEABU22pXK4gAKm21K5XEABU22pXK4gAKm21K5WDXXOfHjWKWsUuIpaxS5il1opZilnibbscVYONTGDHerc07mMGNzjsY6zQ22NjY2q1q2q8VeDiCchyoneomqTg+W2221honaomHRRMK+aiYk+iid6idFE6+m2bbbbb2qJworMUulWhrFLuJaRS8grI1ee2rXWq7RADrzQAAAAAAEAAAQAAGAkCSSMASQAAAgAAdVdbfvbavRtrXXQgAqbAAAttaVNUAAFSoBttttsMOqpOEFwMomHsUTB/KqvEon2rmsYwwwwwwwwwwwwwwwwwwwwyyww1atWrVqwwwwwwwwww8Sid9tWu+3qYxjGMZMWMYxjJixkxokxqLFjGMYxjGTG9Px9vOHOc5znOc5znOcUw4XbJP8onAcqJ5Uq+8k95LklySwQ/ZDQh6xS7GriAAAAAAAASSSAAAH+2tfztiIiIiIiIiIiIiIjIRERERERDZs2bNmzoonKicqJ5qK9xLJLqQ5JaRS9YpdBWhLQhikv0S9iWSHSS9opcxS/4u5IpwoSHxDrNsA=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/iosswrel/ps8802/ps6970/ps6922/end_of_life_notice_c51-462914.html";
data[i] = "QlpoMzFBWSZTWX2Q4HAAAdyfgABnf6AgABgEvitdkEACPaOSUgxkxNMJpiYCaYDv1Jif/qqTIMIwhgQSeqqIEwTTJgCGQTVUFPapvVAE0MmmjPUwDrB7g6wcA8M8cdnb3d+MYxjGMYxjAAAAAAACaIiImBkGgOQeINwbAzmrNW9W9Was1ZqxMg4gvEHSq7Qag7gaQNqtwdgNauoGG247bbqqrlqpttuWrhwAAAAAAAJAAHHbbag2q/9VeAOgeQN4Nw2BwD+hfiB6QPSrvq0q0q0q0qVKlSpUqVKmzbwtVdDGMYxjGMYxjJi6aq+9huD4C9qq4quarmq1C+Atm2vnbbfjVcAAAAAvuq/3NERERERERERybDoDoD/A6qriq3C5qtgfwGlVtVbBah71X1VcBaVX0DkH2LuSKcKEg+yHA4A=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/iosswrel/ps8802/ps6970/ps6922/end_of_life_notice_c51-571251.html";
data[i] = "QlpoMzFBWSZTWbfDViMAAPKfgABnf6AIABgEvitdEDABhgNQlR6qP8qajIDRkDQBFVHkmjRpjUMmmmjeoFKSJpTymEbUZGJoa4ALAB5ACwAQAOG2S/BttttttttvdJJJNYAW9RJJJJJJJFxStKcTrX3U1msazWNZrGs1jWaZ0B/wdQdQcwa7p0m83ndOc48Ad64LZXC0DyBuTpMWTxBsBsDAbTcHUGp2LgGwOauSsBymlaBqcl4K+4OwN05gyYDK6gxwr9g/kXmB6Aek8ZkyZMmTJkyZMmMdgfldl3xbgUADVckGiDCDCDxW5ZLqAHRYS/0WgdAfAPot4vNcRcq+IpqhMWSDJf43oOyDWsABuLuSKcKEhb4asRg=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/iosswrel/ps8802/ps6970/ps6922/end_of_life_notice_c51-586319.html";
data[i] = "QlpoMzFBWSZTWZ8I24MAAVufgABnf+AEABgEvitdEEAB5boEBlU/1UNv1Kho9QAAAantVTJpgIwAAmE1SUnop4KaPU9R5Q00AKVVPJoyhoeoGgMm1LJtoTbXhNtCbawTbV9GHG2rHXcAAAAAAAAL1VVVVVGCba0+bSSSSSSSQABASwScErFM+WhjQxNDg2NDGjNZazWZlrOML/QuMLnC4QufVcq03mGBhlOM4TSeGh5KnjGaMqM4whd4XpR0WKxfOFuhboW0LUL0W0LrC0uUrhC3Qt5WxW0tQsWitQtLZW+F8iu0LvC2HKFkuMLFwKy/ELJe6V4oXmheV0WLFixYsWLFixYsWLFmYsXwheFeq7KxdUraU1VOccpHnI2kbSMI1jGOappG0jrIwVNFToqZxukco3yMo6SN1S3UYyMY/o1kdZHCNlT/F3JFOFCQnwjbgw==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/modules/ps2706/end_of_life_notice_c51-608438.html";
data[i] = "QlpoMzFBWSZTWdTdkpwAAEufgABnf+AEABgEPitZEDAA7NAkqBtINGgAACU9VCGE0GAAAUqp6p7UjTaINBoaMjCHiORDxDhEanZNZC26LCNxGAh4j4RoTCZ1365zrrrr5JtTc4pyJ5p4phNMpvJjamEwymzCYTGU9E5J3BkQJqQYBBiEGM6qqqqqtJB7KCHVNE4JzTsnwmU4p/JonRNiaJlNyd6dE2J/JuTqmE5p4J2TsnBP8XckU4UJDU3ZKcA=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/optical/ps5725/ps2011/ps4002/prod_end-of-life_notice0900aecd804bccac.html";
data[i] = "QlpoMzFBWSZTWeg9AVUAAAebgABneyAJBBAriBAgAFRQDQGmjJhFP0mamRGQGlbeQZeiroFKG7XXOBNn0KyjDfGSGMD3k9I6waRgiiasLuSKcKEh0HoCqg==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/routers/ps10148/eol_c51-698069.html";
data[i] = "QlpoMzFBWSZTWYREVMgAACAfgABnfqAogEgEOiMMECAAiBKp+lPUyaDQNAAKqp+knqeU00xD1D1MSJGpJdhaEAd8mYQ4chMJmYIYLIJfBXBhiakjRy7ujq0SZkzM1JKJ0USoTPBkLkGJUsWFqwhEeyChc4MDI4NCZBubGxuXOD+LuSKcKEhCIipkAA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/routers/ps10912/ps12077/end-of-life-notice-c51-729773.html";
data[i] = "QlpoMzFBWSZTWYTO1dMAAA8fgABnfiAAIQgEMi8bECAAchKpoyepiGgwjAKqp+qeCmmnpD1Bo00rbhq5Krp0uhC+6NFFWSqS7RFs2aTijonoomoue0PruYMLLNmSTdqw2fHVU/Ljyx2IIIXMC7kinChIQmdq6YA=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/routers/ps133/end_of_life_c51-451606.html";
data[i] = "QlpoMzFBWSZTWfLHadoAAX6fgABnf+AAIABEPCtCEEABpc4lobUlDTaf6qIAZAGn6qoaBiaaAwBNVJqj1MTTIxMh6QKipqBHtQRiGTMQkMwkPYSGISGASF8sHPS/fx0t67Kqt1VVVVsqqrdbLcJDICRqqqqAAAAggihBKrhVST1ITEhMSE+JCbcGDaZMmZnhNNTEuZs0aZNZzkJrITMhOxSQp+yDZTuUxJ0KaFOpTWTWv6K8yYTJTNalNCmsUzW8pkppR3KYr8KYkvZMVepTRT9gng4FKUpSlKUpSlKUpSlllKUpzkJ1+6ttLKWSnEpmrsU5lOKi2KbFN+QACIhHMAAAB5k8lP8XckU4UJDyx2na";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/routers/ps133/end_of_life_notice_c51-663704.html";
data[i] = "QlpoMzFBWSZTWXlfLpcABlmfgABnf+AQIAxEPCtCEFAFXs7Zzveac4NVC4kISkUfptCigfqjRoAg/1P2SVQNAAABKn+pUk0RpoAAAFJUUeqHqbSGgANAqUGUTJIHqAAcWhDAOUTrHXfn243ve98Xd3d73ve6qqquSqu7u7u6qrbaySaqskk6AAAqqgAAAAKqgASSSRAJJJXe8QKjiADt5FeBy1y5++XOEzEhPMSE9OMMOufHffq7znN3d61d3vd0qq5iqOKtktoVVVcxVHFVXjjhWyW0KqquYqm5ctt2S2hXd3d3fGHd36+tZ1rWlxz6RMykktwsSTVVVUkkku3vWe93d3d3N3m7rgYGDAAWMNlvphqv5XnLq5cq9tyruAASSTXjUc0rAyI8pResouKV5pITxn3zOOpcx7pnxM4u1llllnRxw4ODgsrZyUUUVRRRRRVGztXauq73iBUcQBO3lFeFzXKefVYmGMeOOenVVVZ9Ns1o0aKKLLl7NzepmyyjRRRRRRRU3RiZyZBwcHB2dw3eYiIV8RxMyklGsQjopmZnaEIQhbnOzpiuuc7Oe4wMFANY3ZhmBueNkR8LhIa8BcrnbsuJRdSi5lF4VPS9JNlz4/Lj9MqdVOjqlz1uumfZIZ/JRZwqZpZ+JRZ2lFj87964bzlFy45W4Wu8ou0uoPeu/ejw627vGD1l+6V4yi5TjiQ1xjHDtM6Qh2mfaJCYbTcDa4XCXC4KxWGGFhYWEwMDoknaJ0nmJ33Ec+HawXEu5OunTsLsLVNU90ouJcS9xXPMRzzyokqoiqp5ENWLuDVre0SE1Yu4NWtQlUVSnuWJdl2tQmnSJjbbMSE2Jh0iY228JgUNybaaGpNNIzlmZyzwB+/P6ImanFTUtS1Go0mk0mk3KnKlKBJJIAASBISSSSScnJSgA6rnPC6upJJJJJJJJJZmZnUovT7bZmOZRekouT8Si8qhd5If6UX+lF/edtss4EvfmZmZmZmWbbMzMzMzMzLNtmZmZmZZtss22ZmZmZlm2xy5znny51gAkAAkAJJACT/cqL/i7kinChIPK+XS4A==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/routers/ps147/eol_c51_511612.html";
data[i] = "QlpoMzFBWSZTWeuKQIQAAxkbgABnf+AIJBgrQBBAAspyWqSEGoeTQVTeqAACFNVU0xNNAZDQoAAAyZAUlElR6ekgBp6iNaAGvLx28SSSSSSSWtBIkkkkkkkknbbbbbbd3dwAf1QH5qA+agP48PD1+33tttuI3uIiG3UzMkkznr7Xe7e7u1d5VVVU223Eb3ERDbuZmSSZu8u9293dq+5YGhoPqhZF9qF8UL/qFyhfHxvjnzzzm8ePHjwvHjrrrrrrrrrrrrrrrjmgAOd6gh0WOidyGGGGIUDb4OBhhhh9kzzwKFCg2ggghQwWMNZg4MC5wYMGCHt8/P9UL96F7PdC+aFw/OhdoDygPogL9U9dyd2FwmxdVEfxRY5tv4oXuhddcoXF9qFl0PFUefGtz1dCgOVHDxEYlBflQv5V/asWLGPV5vWubmXGcfFC9K9K1S1S8vW9a5ucoXFmOP8gPOtPXQ8Rx6C87c92Fw4xgd1cDxx9FAcHQWqiPcTzEiZMzMzMzMwwwwwwwwyyzMzMzMzMzMzMzMzMzMzbM6peqFyhe6F/tC9kj6oX1Qvx3bbbbZm2qqIiKqqqIqqqoiqqqioqqiKqqqb4UB/4u5IpwoSHXFIEIA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/routers/ps147/ps148/prod_end-of-life_notice0900aecd800f753b.html";
data[i] = "QlpoMzFBWSZTWTJgWSQAAAcbAAAFdiBIBYABIAAxAAAGp6ho2k9JJ7FStBBBXsZDIoaggu5fIfxdyRThQkDJgWSQ";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/routers/ps167/end_of_life_notice_c51-706737.html";
data[i] = "QlpoMzFBWSZTWVABQ6AAAJEbgABnf+AIJDgrUBAwAOZISaqPSnqZHqBoAFGhoAAAAqSRND1A0A0yWIFyB7IGRAsQOumbbXhxxVVVcufTbUgfAgakCxA/EDUgZkC+mN+LYviqqqvjHHYhmhe6FUhghdDnipM0KxQ+oWHVDJDLCkLIVakMkKkLVWSB2IHcgVVyBlkqqoJAYd9yqqqqqqqqqqr4CBYgbGZA0IHoh0QuhohohZDZDVDVDZD+LuSKcKEgoAKHQA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/routers/ps272/eol_c51_533036.html";
data[i] = "QlpoMzFBWSZTWRAjX6AAALwfgABnf+AiHABUPitdkDABgDUCJEp6CaU9TR+kgxAAYNNGmmExMmAgaYFKlTZI00AAANNPKa6psFLANt8SSQgdQKD8/iKQkQ7IPVB51133vEx4qunN38quVKl4iaBSwDYHCYeA5Bv4pzFwg90f8DojaDAc1UkkIHkBQcY7TpZdt8VXbvVl3V9/JB27EmKkopUPCDnTzmvHEk+A5st6ZmefPwg7oNoboOEO6DhMLoabHCavCDsuDJnLsO6DF0SMBIhuBnOQKq0H1QYDeRY2xzmIsRYjYbxvGpbJjhF9T0APTrCEIQhJJJJJJYDTTGMIYYYYbBui5i0SyLsi9votC1LaXAsy4luLPBfxcYsizLclnqWRbS6JZS+y0L10lqX+LuSKcKEgIEa/QA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/routers/ps368/end_of_life_c51-680823.html";
data[i] = "QlpoMzFBWSZTWSypcG4ABLafgABnf+AMABgEPitdEFAEHpuO9DdaXFgg4D9tT1VAAAACqf7VUP/VE1GgAAAEnqlSk9TBMTAIaMmG9SpTRtqajJkaGBAClJE0U9BMjQ0MQ9TmCdAT2BOgJwCeXXjju7/Dz444ySbNrdgDVMkit2ANUySK3YA1TJIrdgDVMkit2ANUySK3YAreta1ve+GFrWsqqqqqqqqqqq+Kq14qrXv3/EpMJSYSkwlJhKTCUzCZMGEwzBhMJhMJhmHpBOwJyBOgJwCdepeG8uSPFGiNEayeeuM849MRllGWDBgwaLqvIE2BPQE6VIeYJ3+GZmZmZmZmLQJktV5gnIE3BO8E0CcuWZmZmZmZmLgE8QTUtq5gndUrcE5xOInJWhWvLgAFv48AANrzd3d3d3cAABCkkpKSSSSSkpAAAAAADuAAAcAErd3d3d3d3drWta1iaBNpb10BPKJ9ATuVXxqrXl5AANqbeNa13AANqbAADVNvVVWm3qqkyuaH8kn6BNlfFVPUCfkkkTkjaioqKioqKioqKiosiyKUpSlKUpSlKUpSlKUxJJE3w2xEeEkkTgCfAh6pLxF2F2FoQ+YqvFWq/2qtPQgggggkKCMEREYAAAAAACIiIiIiP/q37flRFEURRFEURQYxjGMYxi81Va9FVT+gm4t5JyFuIegtxfiSZEWUjYWwhtUN5J7C/wtCGInYE/4u5IpwoSBZUuDc";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/routers/ps368/end_of_life_notice_c51-507197.html";
data[i] = "QlpoMzFBWSZTWXlUqqkAA6+fgABnf6AQABgEPitdEFADPS6Dk9LhBzTP1Tf6qoZAZGJoBU3+qpGCYRgmBGCT1VUAAAAADepKTJ6qe0p5J6gAAFKpNqgGTRiYmnqHp1QNIH4QNIHCB57ccc9/j44333338qAAAAAC2SSFAAAAABbJJCgABrWta1rWtboG6B7P3Vq1ZVlWVaMZMmTJkyZMmZkya1ZVlVZbbbZ1QOyB/kDhA4QNuZHI6SOg4h25hmQzmGrUnhAxA6ySI9RA8oHMHlA2QNkCoG0jogd0DJG6BokTZA7xE3iJUDcd9tszMzMzMwAAAAAAAAAAAAIEYoEYgAMzMzMzMzEDYeIieyB2SJ6QOg0gUbREsQnuQKTECk4E/UnWVWJVaSjmlV0Sq6D4SKKLIsiiiiiiiiiiikpOyB8oPfJEmyB6QrSRcxHuLUWotki3yLOS31rbbn3ACgAAIECABAgQAAAAAf1W/eSIxEERiIiIiIiIiItxa2259bbfkqsCwk8BYkXIWBckmUkZUTMWcizksJNBf4tkiyC1lV3F3JFOFCQeVSqqQA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/routers/ps368/end_of_life_notice_c51-676996.html";
data[i] = "QlpoMzFBWSZTWc2ijuUABGUbgABnf6AIBD4rXRBQA7kJ7xXjYcIGVPaqf7VUCYIwJoCD9VU0aNGTIAZMEnqqoA0ADQAE1SQkn6mU2oAzUPUClKoDNJptQNGJjo1rV09QAAAAVQAAAAAAAAAaaNNry000trTTS1tNNLkGdJNfxxLcJAC3CQAtwkALcJAC3CQAtwkALcJAC3CQAtwkALcJAC3CQAtwkALcJAC3CQsaaaWNNNLm/aZMmTJmZMmTJkxkyZMmTJkyZMmTJkyMssZYyzWSPiSO0kb5I2q9BmDBgwYRnUcjUeuw6jcbjgdo6R7JK4SVpJXFQekPkkr7JK1DskrIaSV3JGSR5SRpJGsp5qvmUxHRJXcqcSnMp0qTgfPbfWta1rQAAAAAAAAAAAAABAKoABBVAAAAVS2IiYmyZnbJGqLSF4lYi3pI8FWkitJK3VP5KfpJXhRfmHMMGDIZDIZDBgyMjBg6JK5h6yLZJXdJXgR+JF1h5h5hoR2EbCPCSs5zMwCABAAAAAgQAAAAAAAAQP623P+oiIiIiIiIiIiIiIiIhlmWZskrlJX9SVvDeU4huI+sN4e0phRYVNobCNiN5TxD/Q0Iyh5SV/xdyRThQkM2ijuU";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/routers/ps368/end_of_life_notice_c51-726516.html";
data[i] = "QlpoMzFBWSZTWWh9RnUAAHCbgABnf+AIBD4rXRAwAPgDGAAmAAJhjAATAAEwb1SEk8p6jZEAZNqZjyH4MxyGgyg77qlKlK3HA2HQajMajoLJG49RzG42GBgbDrBgaxLpmnIeg63xa1rWtLWqrYG6aROcGYsLp3T6GQ7JPgZi42SWHMdpH2k83DhaRrIvI7DS1VVSqqq4ZeKlVKq40H8MMJkxI3YdEqJKiXXkXjCfrwtIqOB/i7kinChIND6jOoA=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/routers/ps368/eol_c51_639073.html";
data[i] = "QlpoMzFBWSZTWdbZowcAAVkbgABnf6AIBD4rXRBAAbMS7IYwAAAAA2KqjQ9QNTJgEyCapSmj0jTZQDIAFKoaoYTQZGCZqdWMG+DBuswbkYNz6eKqqqqqqqqqqqqqkwbtMG5n3kcjkcmWMYyxljNkW6L+RaotUWcRoNI5Iu1FoSuSLdFzRajvRbotBwRbIsRdyLZFwDuMGQORg3lgOkDtA8mqqqqqqqqqq1LVVdhg3MDjAcAbbdZF2D7Hwi+iew4jBgwYNVT4pZynCU7kdKW6NY1jMjfsbdGxt9GDPCqqrlVyqqqqq/pty/HLly5cuXLl6DBuDBv8YmIxV6Rgj6jEcaslLJVpGhGiMVd48xmRkjWU/xdyRThQkNbZowc=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/routers/ps4062/end_of_life_notice_c51-546387.html";
data[i] = "QlpoMzFBWSZTWUlGN2wAAA+fgABndKAAAhAEMCNQkCAAchqaNAGgDQKqp+kek01MmjaEss5WVb3qhKjxo9ZzLJSUe2iFkO12psqolqo+IN84jg4XZOV10MMMKPChQPi7kinChIJKMbtg";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/routers/ps4062/end_of_life_notice_c51-729113.html";
data[i] = "QlpoMzFBWSZTWQ/CtXUAAIEfgABnfqAwAhAENCtRkDABLUASSTNqpo/VGmgA0FAAAAAAqKiYU9IPKNBo2piYIYKIg3IXpAXQDQHLSW646pttuczK3Ilg23ttttq02mEFcwZE4gSWjehVTvli2LVaKcLVUgM00BkkGikuaQcTFuTMlixvB1gwJrk8ieZNcWsGJP6DXSyMmeBMGsHQnQmJxBdItjaDumEHWD2RPg2KqqqqqqqreyDKDaD0g6QfUH3B4g7J7waQfsGcjvBUwg5g5g8QcoP8XckU4UJAPwrV1A==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/routers/ps4062/eol_c51_598102.html";
data[i] = "QlpoMzFBWSZTWRYvyDQAAJ2fgABnf2AAAhAEPCtRkDABOACgAAAABQAAAAARJJpohppDTRpmpqic9pKqteVrRyloSfqJzRNUTtpnRRCSRlVVVhEsHWEiSSEJqLouqJwiZomiJfO9pZmUtGoVDSpeqKapqSEmESyJ1RN0S91wrVLtvHZEpwiWXqiWWmPpXDhgDHCJSJ8BoieBiJodETkicjdXB0LhrghJII5kYQ2GFp5FyoQ+lOakWLGPcROiJc7ImSJuPg/ES4vuBJ3FurSJ/Ima+USC0icK8Ins4BD/F3JFOFCQFi/INA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/routers/ps6216/end_of_life_notice_c51-490689.html";
data[i] = "QlpoMzFBWSZTWfaqHPsAAFufgABnf+AAgAAkECuIMDAAxgJFT9Uaam0BGgyFNGgDQAAFKUSbUaMjQ0ep6lQWgL4CqCoC3tTOSSSRgtdm2x6g2NjabvBdgrgVAVgV9VFVQsCoGwLAWg9jgYXguxcy1Lpcyy5FoXIWtsWLUstC8jYw9y7l+l4F9XSyyyyyy+y4LQuxbC3Lcty7lwXBf4u5IpwoSHtVDn2A";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/switches/ps10905/ps10965/end_of_life_notice_c51-726195.html";
data[i] = "QlpoMzFBWSZTWSKaeSwAAK8fgABnf+ACAAAkIi8fQDABLACPVJ7VNNAAAAMYAAAAATUqijIeUaep5J6jE9SIDUANyA0gGiA2Oc8K7E6gknZ3d1BKQXS72tbba2s1vAuougvuLqLkLn9tc9rjtq58NfLa9hcRdRduW22ta222223AXIX5FwF0F9Rcqv0LOws8haq8hdxcKu0Lzp9BcBcC/tP3XnWrVmatWrVq1d4Xzqem222a2vcXxC+BeBdhe1O4ugvgXgXGF1F7i9BesLwL1F/xdyRThQkCKaeSwA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/switches/ps10905/ps10965/end_of_life_notice_c51-728174.html";
data[i] = "QlpoMzFBWSZTWX68xvAAACcbgABnfmAIBCIvH0AgAIgbUkNPRDTQAAilTTTaajI9NIzU9LxSFyJxRFSbNdEVN2ZvhVFMVROJxSaEI4SaUSSYmKQUTRITVISaYJ2TdPieNkiSs0/NSRBBEeU5SwlkumycNkolkumAlU5TRKiXT2nQu5IpwoSD9eY3gA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/switches/ps5718/ps4324/end_of_life_notice_c51-551230.html";
data[i] = "QlpoMzFBWSZTWSmDrG8AAWyfgABnf+AggAgEOitdEEABxcAMJSaoPU9+qk0aBiZACVTfqoAACYmEYYwmJkwEwAAVFKaaBPUZNDRpiaVAIqARoARwAI3gEYbdlNzdxv5c8GzRVVWzRVVWzRVVagEWAIk95yTMiiMCCioqKioqKI0gEXgBFmCegTTOsG3FYtZWtLWy1pa0taWtLW+17BNxvCU2BN4TeE4ZW224CYxVlg9gnME2BKE1GYTWCYNYTATIJqHIJzCYMglP4JRxCUk7CU3BPoE6AnQ4FKUpSlKUpSlKUpSlKUpyCdRP0J4EyCcQncTqJyEomYnkTaEyEy7W22222222224CZhO4TUJgSkPAnwJgmAnUTyJ5CP4u5IpwoSBTB1je";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/switches/ps5718/ps4324/eol_c51_472862.html";
data[i] = "QlpoMzFBWSZTWds7mtwAAMAfgABnfmACAACEOCsMEDABLA0JTVH6p6hoAABKn6VAAIwRgVJTaTUmjRoeo2i0CJokkkgDsCEBEgRpScMWNtsbbtd3d4E3E8CZE8iWJcidaqUGtHQyaLlmCOom4m4mCNhMibCZHyJ7iUJkTuTYSzImhNjsR9EdBLEwYNxMliUTyJoeCUJyTYn4NCiiiiiiijgJwJyJgTsJ8Ccicd6qlVWoCmIFPwFPljYxjGMYMYx/gTyJ6F3JFOFCQ2zua3A=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/switches/ps5718/ps4324/eol_c51_477279.html";
data[i] = "QlpoMzFBWSZTWaensfwAAkYfgABnf+AiAACEOCsMEEACVOABgaT1PVT1H+VJo0DEAZ6lVGhoANAZCgAGgAACkqKZGmUAGjI7ZLZOyzvAssAAAAss/QKoAgVQGAKoDSYy53xZJEnln066Rtu8skiTJJI23eWSRJkkkbbvLJIkySTiBUdij3KOxR/ijuUdCjoPUWMYxjC7+Lt1Op6HQ5unmcHQ6HS55OTk8zweDwet5k+ZR2PUo5JwcFHYo5KO7yzZs0o1Y0vuUYfQoxwKMdSjF6KOSjjpmzZt1KOCjgxj6k+5PQo8ijkVyK4KPLZs2bYoxjTZs2bTGP8UdRXBhWPdRgfCjhR7Cj9ncwwxjGMYxjGMMMMMMMYxjGMYxj2FHmUfBRyUfIo8FHwUfv67AAAAAB1SWyeElsn9JbJ68HBmZmaMhmZmZmaMhmZmZmZmZoznJbJ0ktk/xdyRThQkKensfwA=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/switches/ps5718/ps4324/eol_c51_593690.html";
data[i] = "QlpoMzFBWSZTWR+j03EAAUMfgABnf+AAgAgEOi9dEDABhqACSSjT/1VND1GgAAGMJiZMBMAAFRKRqMgaZGg0aaIENAEPAEKAhgBDLHDVrvt3KqqqqqqqqqrgBDECGR76li1ixaxYtjGYxmMZkxmcRHYRqI2iNRC+mpeqmFVL1UvVS9VL1UaqawIbgIagIwI7xHIRuEeCOAjQRqIojSNojxEZG0RgjEbBFR/CNBHER7CPQRtSToG8RzCOcb4sWLFixYsWLFixYsWNBH4PsToI68rbbbbbVhqI4CP0OgnoFDuDsG4RsDZ+W2222224E1EfojqNgaBRME5hgwR5B2DsI/xdyRThQkB+j03E";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/switches/ps5718/ps4324/eol_C51-721118.html";
data[i] = "QlpoMzFBWSZTWRXWODgAAZifgABnf+AAgAgEOi9dEEABxc4tAZVBPT/9VU0mTTAAASaVRoAAAABNVJTyj0mmhkwQyAKSqU9T9QR+ogNAyPU0S2VLZe0tlS2XCWy7ccNX7r2f20AAAAAAAYS2XGWy5Z5ydRK0StErRK0StErRK2JW4KXZS4UvBS81Lnuxzse/Y52ONjnY52PHY79jzUvJS4Uu9S+om2nvEyiaRN0TKJnNIm6JlPGJlE8qJpEzp+xMTWJiesThE4xPCGsTFPsmJzor0XisssssssssssssssRJgSE9EDwEDySE+cVVVVVEV22222224UvmpeyP4R5IyO5HZHgpdUdfVs2bNmzZs2dBHCl7KX9R1R7kal0I9EdI6KXxR2R2Uv+LuSKcKEgK6xwcAA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/switches/ps5718/ps708/end-of-life-notice-c51-729742.html";
data[i] = "QlpoMzFBWSZTWQJ5BSEAA8GfgABnf6AAEAhEvitdkFADXuPMIikVDGTE0wmmJgJpgMZMTTCaYmAmmArJqT/9VUAAAAAbapSpp6kGgAyAATVKmm1U8aiGRoGIPU+AHQD1A6AaA+XbWuPDx1rWta1oAAAAAAAAAAAAKqqAVVUAAAMIiIiMIiIiMuuZnpNrzNpte97TMzedxm7uwc3Gbu7BzcZ/Weedg5uM8zzzsHNxnmeedBzcZ5m21VV3A0BqA46YOMwc8wc8xVxmKuMxVrMVdgNwPIDIV0lXiBsB8QOoHIDmq3A7AclWgPOFbAaVN1tKqvatu4AAAAAANsAAAAFgACtgAD1VUqq8rb1VV9tU+YG8K8wN5RzhXtJdQMhekB9VXVVirFWKsVYVhWFYVhWFYVhXpAbgvy/MARvg5G5yNzkbnI3OWMy5WcsZl96uAdwfqlfyldgPWr9qnvVyBxCu8l3kuSpzUvLbXwqq+mtbgAAAAAAf9rW+y94ggggggsIIIIIILyqr6KDqD+gbyW1K1JYqeElsat62371VdXrW3tUAAADMzFkbqm0p7SX+kuipiXkDuB/xdyRThQkAJ5BSEA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/switches/ps5718/ps708/eol_c51_588273.html";
data[i] = "QlpoMzFBWSZTWVylbYsAAJmbgABnemAANL4rXZAwASYUEU1UzUYmgAAaGMABMAATApUo0ZJp6mhoGTTJrBMQTwCbASwJnjaSSSSSSSSQEyBLGdHWmUSglTcCaAlgS8EyBJhXCtk0JgnInkTcriTaTzJqTkTaTcsycCbFmTYTQnUm8nYmRV1uJMU5ic631isVhYWRPUzwYYtV4V+LisyftOi0jxaXi1KfFLlMAS9CVVVo+ws1TVFwJgCYK7E3L7Jks7A1slfRMWaysjXDGGMh0Xe0pi7q8E/xdyRThQkFylbYsA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/switches/ps5718/ps708/eol_c51-624522.html";
data[i] = "QlpoMzFBWSZTWQnCIbUAChQfgABnf+AAQAhEvitdkGAHX2A8BvpYFkt8xgElAGGCYEwENGTTAyf6qn+qn/qqfp/6qqAAAABW3qqgAyAAAASn6lVUzUwmhgCYE2gmqUUyaD1AAGgAKUogaKeo0HqbUGj1NqcRSchSfsUnIUnAUm2/twzm5+jp6r4mICjEBRiAG6AoxAUYgKMQFGICjEBRiDWtcmprWijEBRiAoxAUYgKMQFGICjEBRiAoxAUYgKMQFGICjEBRiAoxAUYgKMQFb7bbcOG3Dbfau66/q+fswbY7bBtjtsG2O2wbY7bBtjtsG2O2wbY7bBtjtsG2O2wbYswNsdtg2xGaJbaM0S23GaJbYzRLbcZoltjNEttGaJbaM0S20ZiW24zEts2xLbcZolt56u668aqTgKTgFJt1K57itNJW4rXRGmyNkcEbE25iacpNaNqiWwpPqKTBS+yV6Ck1FJ8xSdRSaCk3St4pPiKTRG+olz1E1qJbxG6psrDu68Lru/iruunXcq7AAAAAAAA64AAKAAAAAAACAAAAAAAAAAAAAAAAOq4AAAAAAADzVEsqJao4VEvsR31Et1QuwpN6pPSMlcxSZK4RgrBSwSewQ7hSesrnKyGIxGIxGIxGIxGIxGIxGIyjKMoyjCYTFWSu4UnEUnrOWLMWYsxZixcXFxcXFx3FyVyVxcVSWqWlVaWlqvv4AEgAAEgAAAAAAAA00laStKXUUeaidgWqV4BdBSf0KdxR0EnkR5EaBTwFNQpsKToKtMzMzMzMAAIiIiIgCAAAAAAAAAAAAAABAeNXV+LwEEEEEEEEEEEAAAAAAAAEEEACIiIiIiIiIiIiIiIiIiIiIiIiIiLMZjMZmYzGY1EmwpNqieBSbxGoLgIwKfARqKr2V3XSrvDqu8iIiIiIiIiIiIiIiIVXeSqpqKP4I9xHEKYE2Cnvd1dePqAIAAAAIAACACAABACAAAgAgAAQAgAAAAgAAAAgAAAAAAAgAAABJwAAAgAgAAfsXckU4UJAJwiG1A==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/switches/ps5718/ps708/eol_c51-697077.html";
data[i] = "QlpoMzFBWSZTWawjj34ADFWfgABnf+AAIAhEvitdkGAI32APAMT6kFoYfHMAKUAGGCYEwENGTTAiZVT/9VUZ/v1VVNNMAg0yZBGeqqmjTExGIaBkASeqVU00nkmNQMTIB6gmpUpPKZGmTINNBiYClKaqfqbU9U8oAMjQ9Rp0oS4oS9KEuKEvChLx2zd4/T651fbr+87NWqGBGrVDAjVqhgRq1QwI0qGBBaoYEatUMCNWqGBGrVDAjVqhgRq1QwI1aoYEatUMCNWqGBGrVDAjVqhgRq1QwI1aoYEatUMCNWqGBGrVDAjVqhgRq1QwI1aoYEatUMCNWqGBGrVDAjp5yqrlc6ecqq5XOrn5mVd3dXdVmZBG5yCK7ugiu7oIru6CK7ugiu7oIru6CK7ugiu7oIru6CK7ugiu7oIru6CMcuEY5cIzuuEUcuERy4RRy4RHLhGOXCKOXCI5cIxy4RjlwjHLhFHLhGOXCe7arW9dqtbx2q1cUJdKEurWRdnTItmYLTMpc5FjbIt2si7NZFjbIuzWRdmZF7WZFy3yLG2RctZF1oS5G3ntWrX57Va36ewAQAAAAAABtZtZtar02qTUdBUnYVJ2FScFScvhtsAAAAAAAAcypOAJxRzKk+dUOgqTmUXIouVRwVJqOONtttttsAAAAAAANtgAAAAAAAAANtgAAAAAgAAAFbZW2AAAAAAAAAArVpxRzKk9Ci7ypOqqH3Kk3Kq4oSwrcKsK9lCWBP9UNRii8IqT80dVGo1GJiajUajUajUajUajUajUajUajUajUajUajUajUeEVJ0lSfT8sXm5i5zFzmLnMXOYucxc5i5zFzmLnMXOYucxc5i5zFy5i5zFzkXTmMYunMYxc5i6cxjFzktxVluKstxlWW4qy3N3pxAAAAAAAAAAAAADMkZkjMk3SSZJ/TJMH5Ku5V1oS/kJeVUrqiXqpHqpG0Jd4S1CXFCXKtrgAAAAAAAAAAAAAAAAAAAEkSSSSSSSSSSSST1trV6XjJJJJJJJJJJJJJJJJJJJJJJJJJJJJJERERERERERERERERERERBgyYMGDBgwYMGDBgwbwtWt5bVa3lrap3oS3UjRV4KRkJdVI1bVtfxtVrLbeNtvCtsAAAAAAAAABrbeGiWqKfpSP8pHSEsinjCt/2tqr8fWAAAASAAAASTAAAMgAAACAAAAZAAAAEAAAAkAAAAyAAAAIAAABIAAABIAAABIAAABkAAAAkAAAB/4u5IpwoSFYRx78A==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/switches/ps5718/ps708/eol_c51-698004.html";
data[i] = "QlpoMzFBWSZTWeczmCEAAQMfgABnfqAgAEgkvitdEDABawKEap71UAAAAAI3qqnogaABoAAmqURPTURptIyYjZNJGSUbJLhklAySiZJXTT0AAADu4AAWta2TNUkVJNnUAAFABtqSeUOMNIdoeENt6t6u+anOH5hkN4c4bVXjDSG8OUNIcYbw4wyHWG1OMMq5Qyryh5w+obQ8IfMPSHrDvh61ZVlWVZMmVZVpQ7oekbj4q61d0Okf8axzqu1X6q0jpGscob1aZmYAp+qq9ZQAAAUF1STTQ6Q6xwq1q/0bVaR+KuEXvDXxzMzMzMzMzOEcI+IbVfVXKMO0PsXckU4UJDnM5ghA";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/switches/ps5718/ps708/prod_end-of-life_notice0900aecd80423d31.html";
data[i] = "QlpoMzFBWSZTWUjtaSEAASUfgABnf+ABAAhEvytdkEAB45hKBtVPSNqmybVNAA0ABJ6qpR6nqBgjJhDADDIwJpgTIYmjAKVQUzU0DJ6gAaD1HASsAl3AS1AJTASzak+GVolrzbi7u7vbbWuNaUpKlKznPDCtcUAlACVwCX4BK5AJXgJXxCiJszWVpWZmtENfKTunTp1gsllAB1HTUa1GJ2p21HGoxZ1GCHKo1qMqjdnhvivSTFUaVGDPS2rhtq42r0tXLbV8tcRIEgSaCXLWuHASa2k21LjtqV47au621dvJJJJJJJJJJISEkkkkkku621dOo41GmvfjjgwY8UbVGJpUfUnKTnJ7I1RsjZGMnjJhJlJ8VL86172r53qEgSAwAJ/pM6jhUcKj7qNyN6M5NkZVHYjJGUm0mcnNGyN8m1R0VH+LuSKcKEgkdrSQgA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/switches/ps6568/ps10956/end_of_life_notice_c51-726192.html";
data[i] = "QlpoMzFBWSZTWRTD95wAAF6bgABne+AIBKIvH0AwAMYCTVUGmBPRpAeoCgAAAAAUqUamQMTyE0bU9S8J0Cegl4S4JTFVVVuCU8IxUbfoootQmITUJUJoEymSMUsEQlQnX2YYxjBmXUsy9C0LQvcsiyLkWC8FyFwHEtxbj9XdcFhYWRaGpdhalsXYvC1L6LyWxbxZl5L+OhfYti7l/i7kinChICmH7zg=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/switches/ps6568/ps10956/end_of_life_notice_c51-726193.html";
data[i] = "QlpoMzFBWSZTWYtcV+4AAC6bgABne+AIBKIvH0AgAIgSKgNNANAACKkanqaDTT1PJNHlPUrBcirFSKBi26RY7jH8eNuQoiyFIUBR6kIFhzGY6BQkB4GI7DQchmPcaDIYjwOoPM0HIcg+u5IgEAiPouNQbjgajw3HYbDgcwZjYfxsNQcDuP8XckU4UJCLXFfu";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/switches/ps6568/ps10956/end_of_life_notice_c51-726196.html";
data[i] = "QlpoMzFBWSZTWUYqonIAAKAfgABnf+ACAAAkOi8fQDABOADGExMmAmAAMYTEyYCYAARKTIjTKGmyJ6mNT1MBE8omCJZE66W0M61rXOWtnfrheX0RO2zIyMkkhJwiaonwiWRNUSImXKY9KQr0kyjSX5z0iVRNETvmSEhJJAMTqiVRPtE5olQLkTuiUeSJkiXIlzgiXIlALImyJQHVE8InNHFEwRKAeV/HmyRjJGMYyRjGOwiWRM75JIx9om4iVA3ROETRE9L4ROyJuicIlwiaontE+kTQROETVE/xdyRThQkEYqonIA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/switches/ps6568/ps10956/end_of_life_notice_c51-727634.html";
data[i] = "QlpoMzFBWSZTWRc/PRkAAF6bgABne2AIBKIvH0AwAMYCTVUaep6mTJ6hiNGFAANAAAFKVQ0000NPSepoep6VCVCfAlQlAmVyqqr0CZaIxUdt4oovkJeEsEoEqE7RRimwRCWCcy68mMzMPcvIvguhcloWLgXAvYsLsX0LmMLD9XqWq81ixeBdTYtRbFuWpfi2L5L+LcvEWhbF/nQuwty0LuLuSKcKEgLn56Mg";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/switches/ps6568/ps10956/end_of_life_notice_c51-728173.html";
data[i] = "QlpoMzFBWSZTWSZJ8/4AAEcbgABnf2AIBKIvH0AwAMwDNUhoA0AACgAAAAAUqSTRp5Q02RNMTSlpVtLlpVNKLSlZRCABFpS3AAXfwMDWNI5RwjOM7GVljvGkaxtG83xg2jjGI+4xGcboyjrGsevOMcEZxiOx0OBgwYxpGx4jmjxHmNo6niNY7x5jcjnHaP44x0R5jlH+LuSKcKEgTJPn/A==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/video/ps8806/ps5684/ps2209/end_of_life_notice_c51-669670.html";
data[i] = "QlpoMzFBWSZTWSXrWLwAAFofgABnf+AYAAgEECtSEDAAxpCJSTZNCBoNDQo0NAAAAFKpA0AABksDkDuDkDUG+emvPp3rpatcAQoDwDQHEHUG1LXtkXxyrjqDgDcHFG8Rn4HxsFhzLQXQsC17S+lmW4tWJaC3ixB2B8g6WkjKg0pwDSkkMwaAO4D7vJJJJJJJJJJJ0BgPMH6DgDoA/gsiyLWXou5Zl/F3JFOFCQJetYvA";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/voicesw/ps6790/gatecont/ps3869/end_of_life_notice_c51-676985.html";
data[i] = "QlpoMzFBWSZTWXKBbH8AABcfgABneMAIAgAEGDNYECAAaiv1TRMj0mEaNoR6Kh6gAyNCYpk5JEb4QyaLjERBSUJqIWFHlDAh5wUHIxxF4yTkoVgrKSUmcMUbEnoixYYsMMbF3JFOFCQcoFsfwA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/wireless/ps11035/ps11047/ps11072/end_of_life_notice_c51-676976.html";
data[i] = "QlpoMzFBWSZTWUI6RdEAAFsbgABnf+AQRDgrCRAwAMZQk1SR6ZGoGgDQo0NAAAAFSShmoNABo9S4TS6LJ8CXCZhOuuVcWty59L3qE9BPoSgTcJrAmkWS2L344tnjFc+YShYJlRUNgnQlE4k6o7o0JdncSy1yZMm4m1cSsibCWpFUipqSlEp9J7E9Myqqqqqq1CeAlAlwmoTcJuE2EwTUmCZksTBME7E+E0JwJ/F3JFOFCQQjpF0Q";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/wireless/wirelssw/ps1862/end_of_life_notice_c51-534051.html";
data[i] = "QlpoMzFBWSZTWdGpb8UAAAefgABnfOAAYABEECtNECAAVFAANABpoNUbRppPU8oHqDJVe0N6LdsTFjsQRhorFRwe0puhXzFfYHKQIl4/kCJYU8vi7kinChIaNS34oA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/wireless/wirelssw/ps1862/end_of_life_notice_c51-676983.html";
data[i] = "QlpoMzFBWSZTWc5yA5IAACWbgABnfqAIhBgrRBAgAJAoABoGTIEUij2qepoekabU9S6Sd3lLpKY2IiU6SRnCYTSUSUsbNLkGyXKO5CbpRKyQQejcwlkq1eqXbJD5ZSqUJEulVPqZTsnwsQw8CVSiXTlPCcJCZTKTpKppP4u5IpwoSGc5AckA";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/wireless/wirelssw/ps1862/end_of_life_notice_c51-713531.html";
data[i] = "QlpoMzFBWSZTWaTtqecAAA+fgABneOACIBAEECtNECAAagqqBiNAAGgVVMjTQAAaJL3S9FnOKL5mouaIIymgaLU1jFJYgmkuRSVSZJtEFFrxyb3QhySRdr1EHr1RutfKPxdyRThQkKTtqec=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/wireless/wirelssw/ps1862/eol_c51_636690.html";
data[i] = "QlpoMzFBWSZTWRKpjFQAABabgABnf+AIhBgrTBAgAGobVTIepo0GQaMg2qaTIyNBoaAgMs6EBiS0YobyXBYiMXKLoKJMeTNhg3VSq2GHvgTiOiMWL0SHi9Y8XKgnOsiYxI9IlVIcVKmRZP2Zyqfi7kinChICVTGKgA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/wireless/wirelssw/ps4341/end_of_life_notice_c51-525258.html";
data[i] = "QlpoMzFBWSZTWcjg7dkAANQbgABnf+AAZBgrCBAwATGNoSp/qqjQNGgAAipMjTanqhpoMgRJTU9T0jIBoZqC4BeQXUF0Bd4rTa89u9rR43jEUveIi1oiKguAXoFqC6Av4FoC3BazictTI0MEkl88zMwSR3BdCAWhcBeAFmtJIRSwL3BaLAsDwC+gWgbySCLDUFuC5AtwWWkwC0UYBaBaICwgH0FgQFocgWH8XYBdjBCSSSSSSSSSSSSXYFoCyC7AvAvILQXoWwLQF6Bx41AAEgE/VjH8XckU4UJDI4O3ZA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/wireless/wirelssw/ps5940/end_of_life_notice_c51-523626.html";
data[i] = "QlpoMzFBWSZTWU7gDuYAAHobgABnfKAAZBhrCBAwAPgCg0aNBkBoUGjRoMgNAqqfqFT9MieqaHo0mAyHsMBcNcfXO9PGr3te9L3qGA7CoXD4EDcK5pmlKWYVZX5DgLg8gyVDwFQ0FnkI9BGgRyG4VDcLMhGQtsKSRsRt6CKhHY6B0wiIiIiIiIiP0IHAaDgewg7FQgdh1SREkkkT4H+LuSKcKEgncAdzAA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/wireless/wirelssw/ps873/end_of_life_notice_c51-533811.html";
data[i] = "QlpoMzFBWSZTWcAFiiAAAF0fgABndOAQAABEGKsIEDAAxiERVM1PUGgBoUGjRoMgNApSmqeoyNBmptRkHIP0HIOAdufCWWWWYBoP4HiDuDqDQGYIzVpkGNBjoA6WSRGSMZHYsvQupaL3LcXYvkty0W4uhcF+lyaLDgXe9bLLLLLLgsLqXwXA8lhyNFhclr2022zNi3cH+LuSKcKEhgAsUQA=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/hw/cable/ps2217/prod_eol_notice0900aecd801ef222.html";
data[i] = "QlpoMzFBWSZTWct+AZkAAyQfgABnf+AKAAAEGCteEEACxByESOIj1PJpUGnqAZACElVNA0DQGmgKAAAAABSkk0JomPUhkY0mLRaLT2zx05ZMyJmZMyCQSMttpsNttKG8k1VUlVYaBIJBIxfF8qkVdJImEAkj6vcD+hEfYIj8hEfL414fDuqaqru7qmqq7u6Kqu7cRVFVXduIqioqKO7cRVFRQiPgAj6fz02xttq22NtttsbbattjbbVWNqxtWNqqsbVttttsbbbbbbbbbYpdkl3SXCS2n64ms1PLPKcGcGs6TiZvNdV1tl2XSdLmuS8C8/RYsMeO4cncMlDJSSSRDQwwyB5CI+IiOVF99VFVU1VFVVVVVFVU1VFVVUlEVURFDVFVQKP4BEfBBMIjkT9lukv6XpKfxJdElvHKMlktJLRaL5ItLwSWy5yrmktoh1WSxbrFusWk0mDAh9oiOH+iI8DgfBRHVVVVVVVWwyQw+YIj5oj4ojIJJMWLFi4SWJLukvNHMh9JLCPshiSxJfaS7Q2zMVySWByzMgzMyH0R6pLukD8XckU4UJDLfgGZ";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/hw/modules/ps2797/prod_eol_notice0900aecd801d723f.html";
data[i] = "QlpoMzFBWSZTWbASVOwAACYbgABnfQBAFBgjCJAgAJAo0ZA0aZGgikRmqeiaYaS6SnaSlk3xa21E7TxNElPU1SqWmdNMJVKpwJqSmyVTdOEomtkulLJRLpCVolEo5ToTmYiIiIiUhPyYTxOkylU+JlMp6nKXT+LuSKcKEhYCSp2A";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/hw/optical/ps2011/prod_eol_notice0900aecd804bccca.html";
data[i] = "QlpoMzFBWSZTWYZLpm4AAD6bgABnfyAJBBAriBAwALgKDRo0GQGhQaNGgyA0Cqp+qDITTE0yepUbDsZig41kkkoMRe6uiYCwg5GgrSJI0G/CJJUcDAUKkPQ2GQsIKjUMRBuOR8KCF2IzFQ8OihCH0MheMx4Oy8QeCw3HYsP4u5IpwoSEMl0zcA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/hw/routers/ps130/prod_eol_notice0900aecd804b960a.html";
data[i] = "QlpoMzFBWSZTWRb2PvQAAEqbgABnd0AABBgjCDAwAKahEop4I1NGgKBpoZGTEEUKAANNLt10PMlOxIJgTAl2qm59AhmQ2thI2E/CeLQeDyt+RItg6jSLoSglhKRhloT0ShORIE6OzESYWcBJarVesiZWMWm6iXDgTQmA0J2JQSwlhKCum8EpJcT8XckU4UJAW9j70A==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/hw/routers/ps221/prod_eol_notices_list.html";
data[i] = "QlpoMzFBWSZTWT3b5n4AACWbgABnfcAGJDgriTAgAIoJJqk81TRkxA9R6nqCShMR6jRoABMhC4dkZolGxvs+chX8iA3RvQMIhhC0m1ybBDIeiaKoghyJwB2NckRRwiQPinyRVVQwoEfK0uY6CNSUPys1EWG7UCxkjVH1GgroujjImMDbeEfxdyRThQkD3b5n4A==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/hw/routers/ps341/prod_eol_notice0900aecd8049f17a.html";
data[i] = "QlpoMzFBWSZTWctE0W4AATObgABnf+AIBDg7SBAwAYYAwkVR+mnqoNAAaCjQ0AAAAhUiGJqDT1AekygRuQI+IERAi0CHW/HDjpy53iqqS5mSS8VVSXMySXituUCIgRqasbGxsbKKKKKKKKPCCeUEkE6IJugnbs5Ozm7O73d3R6vRzczM9UE2dkEnYQSEE4HJBOEEw+6CThBIfCCTwgkrkgkIaoJhBOzogkCndBNEEwInWqmfoXCCmKqZgBqqZ/EExioIqqJjlBPt1ZmZmZmZmZmZmZmZiJn4QTcXCCaoJgX9QTgXCPPNVVVVVVVVYQSQTlBN0E8oJ8XckU4UJDLRNFuA";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/hw/routers/ps341/prod_eol_notice0900aecd8049f19f.html";
data[i] = "QlpoMzFBWSZTWYLdxRYAA5sbgABnf+AIBDw7SBBAAtpndaqhHcVU/81VEz36qgAAAk9VTVNJmo0AA9QIqm0miaeoxMTEYFJSpqB+qZMT1AGXCK4CK8iK3iK0EVywiynmt8REevePFyxVAFVyxVAFVyxVAFVyxW2qq5YrbVVcsVQBVcsbv379/X187W29NVXoAMAElV414lkslkslk0zUlksZZlmWaZqzgeCVeyVZJbRFfAit1VlNZUAkBaBVarQJzB2HYdh4jyryHVeaVfQdKlh1ba3estbb38AAPKsrW262RouJV3SrgeiVYcSrFa1tlr022urW27cAAPO1turQcHSpfFKvBKvVKu6Vc+G22ATZV2rfiq5wACbKlqr5JVubbbWziVcnFH7SrA/9U/Q+owwwwwwww1atWrTTDDDDDDDDDDVqwwww7pV0HEq8U23VVfu1tlV86pa148AAAAAdWtstbb+2tt7cAAgAAeHl2uuOcuuOcuuOcuuOcuuOFIFISymKQMUgYpAxSBikCkBlFkR0Ir2LuSKcKEhBbuKLAA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/hw/routers/ps341/prod_eol_notice0900aecd804a02df.html";
data[i] = "QlpoMzFBWSZTWSyGSLEAAtcbgABnf+AIBDw7SBBAAl026BW5hpp6qoH79VUAAAGeqqABoAB6gb1KUBMeomJgECkqKmNPUJiaANPAF6Av4C7Au8F7dc7v8tvP0+vr5e3XGraqq8atqqrxq2qqvGraqq8atqqrxqqq9ckkzmSZnLbaUABFtxZhKSkpKiWEuy2Wy2Wy2rcgvkFgXcJGySSNmYzqjH4YNcaUxgwZMmTJ1XS9QXjXRJq6JOiwLy5222222+hYC4WrKcAvgFxL2BZcAsWBe4L4BdJOQXh3bbbbbOwLhRcV5knYFzBc7bbbbMtXJfhXCTkFlfoFwC4rAtJ/kn5rxrVq1aUpYsWLFKUpSlKUpa1atWrV7gvNXALoFwV+ySVLectSSzGAAAADNJJMskkz8kkmd2Zn7TpmlCaUJpQmlDShpQmlCaUJpQmlCaUJpQzSnPyC/4u5IpwoSBZDJFiA";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/hw/routers/ps341/prod_eol_notice0900aecd8067a439.html";
data[i] = "QlpoMzFBWSZTWdOtpegAAmAfgABnd+AEAABEvi9fMEACYuA5mthKJCfvVUAAGgACTSVRpkeoYQGmhpkE1VQE0ehoQwTJo0BSVIU8kPUDQBoDRACDsAQUAQYAEGvLdOYyZ9OrW0yqq0yiqtVVX3s4YYKtMoqrTKKq0yiq3gEHeCALY8bRjJddaLpLTFpLTFpgXMsxMyzEzLMSsqVlZWXskNgBHmEwJ1CdO9cvXXHeuK5Gw6DuO9d67L2hOquoJ2CeHLbbNtttq1ZDgJ4hPcE5TgJz4bW222kqw8AnMJyCcwT3hOg6hPEJwLgJlfYJpPwpatV9AT5jsMMNWrVq00wwwwww1atWrVq5VSxGMvYLrF8xaapY1S5k5S5heEnlL9Syk4E8LOTCqGhIUA/pJNnc9bVtq21bSirbVtq21batpVthSHOGoAhoAQ5gEdE6SeQTmp2k3PbbZm2222ZN0IdSGoAm2Q0IdtVVVVVVVIaCZyYSwL3S0S3S8payZJOEvMJ/xdyRThQkNOtpegA=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/hw/routers/ps352/prod_eol_notice0900aecd800f6189.html";
data[i] = "QlpoMzFBWSZTWQ9ceL8AAFUbgABneKAANBgzSBAwALgKADEaaaNCgAxGmmjQRFSemlMZQ2mjKmVOVNlNVNzExbbYD20ZCToOoSNOynCnxSqaKTKUr+KbPDopAOFNFMKalAqlPKnCmFN1IpqpFMBspkUoYUqn6pyplT+TZIQgQP8U1UqmVOVPAJ7U9qUvUkhJ8U+i7kinChIB648X4A==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/hw/routers/ps352/prod_eol_notice09186a00801fd14e.html";
data[i] = "QlpoMzFBWSZTWcdRNAcAAAmfAAAFfKACAABFgAEgACGp6E0YmQpgAB2kwFNdHBEICMtFoT5gp1mS+zXxdyRThQkMdRNAcA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/hw/routers/ps368/prod_eol_notices_list.html";
data[i] = "QlpoMzFBWSZTWTknx/YAA/cbgABnf6AIBD4rXRBQA104xxGkSSD/9VU379VVGBBgCZA03qqk00wEMAjQJPVVJkJgamAJpgmpUptSbTQmQBoaGMAAAABzA74H6gcQOYHz6dfby3pzzz053PJiDEGIMQYgxBiDEGIMQYgxMqqqqqgAdVttu+223Pf6RSZIpMkUmSKTJFJkimZIpMkUmSKc7bbcrbbflsPlQOO0cUdo8Y7Jo3JPaB6QOsDulTvqJ5QPOVPnA7UdoHtA4o8YHrA0DvhmaJMzRMzMz7mTMnxJkmuTJN9AAAAAAAAAAAAALbbbbbLbbAAAcccccccccfKB60rwReFRkWo8aBqNA1HhKnRF/EX4lT3VL7x1jUajRo0aNGjRrZWytv5bbbs7gAAABptk9FS6QPSVPcqfZUvInwT4JwVPMqdxU94G6622ttoIIJCCDAAAAAAAAA/Nrcv+iIiIiIiIiIiIi2tra2tra27oHWB/YHQnRFyToVPoToT1vPLa2W1strZEacKrVwuDRGiNEaI0RojRFGNOO1uO1W421uWi9yf4nBU0T4gf8XckU4UJA5J8f2A=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/hw/switches/ps4324/prod_eol_notice0900aecd80199950.html";
data[i] = "QlpoMzFBWSZTWVrwhXQAADwfgABnfgACAACEOCsMEDAA2AUGjRoMgNCg0aNBkBoFVVP/VPUxT1DUaY9TS46D2OguN8261VVQsNCCw5HAwMYWUrIwLCChYcB/NhG47Dcdx+jqLsiLjYaIKQRgQ5GR4boiIiP8LjQoZHY0IfCCDQ8bSSJ8HI+i7kinChILXhCugA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/hw/switches/ps4324/prod_eol_notice0900aecd80256100.html";
data[i] = "QlpoMzFBWSZTWYTPfoAAARofgABnfiACAACEOCsMEDABZgIJT1NKIaAABQADQMmQFRSaTKeiaDRtGoUHHcqqqqqqqqqrR7CgQoNQoOmm3GSTlmZkkmZmZJJmZmSSZAoOhDyQpDUhSHohxMFilKUo23NjoaTfJkyZMzBHBDoQ1ENCMEMkMEO4hsMEKMEMkOpDBDsHcNRuQo0I0I1IZIeUNRPRDchyhqCofg4FFFFFFFKeBD5IckNCHUh2IckP/xbaqqqrAoNgoPgUHjR0bbbbG220W2222xt+hQfgoP4u5IpwoSEJnv0A";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/hw/switches/ps4324/prod_eol_notice0900aecd804be204.html";
data[i] = "QlpoMzFBWSZTWaocmjAAAPIfgABnf+ACAACEOCsMEDABTAYJVAb9VAxAABKqf+lUwJgIyYAVVT/VGj1Q9TQDQaEAIgB2AFwAQADTCGOUZTVVVVqqqqqqqqyBwB9BgD8CA4A0BncxLFy5cuVu0ByAyB2BvBxLAhAcwWB0B2B3DEGZQOYGBQMAWBiH4EH0IFgMwbBYNSiEIQhCEIQhCEPQHkGwMQXBoDYGvSSRVVV9gB8ADkAMaWljGMYxjGMYwY9AB2AHgu5IpwoSFUOTRgA=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/hw/switches/ps708/prod_eol_notice0900aecd80699ddb.html";
data[i] = "QlpoMzFBWSZTWdxMTe8ABk6fgABnf+ARAAhEvzvdkFAFfQ57pVsoB4ucNHcQeypn/qqnvzVUgMgaAAEeKqj1AZAGCAABJ6qomp5T9UAAyAAAmqik00wmQNAAAApKSin6U9qR+qNANqAHqaahJ31TeKXsJNYk1CTqzt1d+7o6c9XXjwAA3dqsbbm3CAAqsbbm3CAAqsbbm3CAAqsbbm3CAAqsbbm3CAAqsbbm3CAAqsbbm1ANu1ZdLJJJJrNJJJJJrNJJJJJrw44444444467a1u3YAAAAAAAAAAAABtskxNJhe4XionKpXzqk0iTcJOmqaxSzXRwbNDOWeWvQ8Hg8Hg9Twd63cetd+9c5XO47113rnK53r7PhXPKuq67DsOw7DsPMfAbTgJNtTiJNgkzV24xjGMY3iLctbDwODBhhhh91SWq5RJippEmIjsqnbVMCk21a61dNtazuAAOtdtta3PUlww6HpUlypLzqSw9olo8tttttttvM6VLqpLhh0PzW5cgADnVyq5VAAByjg4NDbbbbbbbcHBweVSXObbbbbbbdDg4O1SXJEcHRyomOBq21f0hPZUl8j6TGMYxjGMYxjGMYxjGMYwwwwwwwwwwwwwwwwwwwwww1asMMMMMMMMMMMMMMMMMPZUl8akvf4ns4KSSSSWJOCkkkkliTgpJJJJJOCkkkkkkkkkkkkliSatmlVVVVVVa8yMwWMODqvtSfOonySdB7pPhST5EnESfRS01U9ZLhSXxJbZL+ktBS7ylgSchS3C1um1a/1rSrey6QkJCQkJCQkJCQkJCQkJCQkJCQkJH91vQAAAH321rdNta3m21reXUT3qS9CT8S8knmXqk5E4bta101WrrrXcRERERERERERERHOteciIiIiIiIiIiIiP8BhhoAH3z5pWWVlWLlWVZVlWZzmznNnObPzSW+qfkluKX8KWsSf4u5IpwoSG4mJve";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/hw/tsd_products_support_end-of-sale_and_end-of-life_products_list.html";
data[i] = "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";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/prod_end_of_life.html";
data[i] = "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";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/sw/iosswrel/ps1818/prod_eol_notices_list.html";
data[i] = "QlpoMzFBWSZTWWZUNf8AAAgbgARncqAADwABAAQgADFNMjExMQp6jRppo9TIMlMUZNu/uBVhCwUza8NM/F3JFOFCQZlQ1/w=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/sw/iosswrel/ps1828/prod_eol_notice0900aecd80563fea.html";
data[i] = "QlpoMzFBWSZTWbKNamcAAA+bgABnfkAABDgjADAgAEgqqHqNDJ6g0AqqZNpAaNGjRSboUUZPUrJfOlbcuGpCpmhdKF1FSju8pVasoJoeoYYTfPxdyRThQkLKNamc";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/sw/iosswrel/ps1831/prod_bulletin09186a008007d987.html";
data[i] = "QlpoMzFBWSZTWd8DaTUAAFebgABnfuAEBZgjCDAwANhooAAAyZAzVRpo0AYQBFJomp5TTI0BpoplTb4phS5ECWrOdt52xva3RT8pdToD3B5U4vcHKlL3xM9bdba7Ka5zhSlMKQjKPFgYU0qpoDcqDG6kUU8/FJCbYgGTRGgMg1RqSpwpT0pDMRERaKe7YgAAAAABpFJyjBtXNrttSbXjasDRTdTlTlT+LuSKcKEhvgbSag==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/sw/iosswrel/ps1838/prod_eol_notice0900aecd80481a49.html";
data[i] = "QlpoMzFBWSZTWXiQB5UAAJ+fgABnfqAYAAgEGDtIEDABDBBEqm/VTQYgBkCmjQBoAAClKRiTTIaGhpuCJkiaonFExROvPHLO22222226YIt6vDwxjGMYxlot5P+TWThJ0k35mxqczmdJOUmsnGTWTY4SYfEmsnWTSTtMk4m0m0mhrJpJ7ydpNpNR1kxN0n5J4mkndJ3SdzkYYYYYYYYZmiJETRE1RMwQ2RNkTthJJJIYfZJJJPyJ/F3JFOFCQeJAHlQ=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/sw/iosswrel/ps1839/prod_eol_notice09186a0080186d83.html";
data[i] = "QlpoMzFBWSZTWSrPLj8ABSybgABnf2AEBZgviDBQA/a9xAABwIqp7baJKCGIwAhsqkaNADJoAan+lUlBoyYjTTTRigAGgAAClIgimEjaR6ajMauru6x3AAAAZKqqqqrxvC6ZJAdgAA3btVVVVVVVV0gAAAYKqqqqq1dIEkkiq73veta1rWp7/oKeoU+0KZw8d9+/nnj35W4V7ArisExWLCzHUgmKCwsx1IJigsLMdSfjIxSqtGtgTi0aZGKVWka2AHDT0y2KVVowsjq5bIxSqtGFkdX3465765473vxxy45CnkD/wpgV2FPGfs+phkwyYZMMmGJhkwyYZMMmGRYYsMWGGYwyYZMx0FPIU+MaTI6jzNx3cRuZHCOI4jcbjibjaNxubtq4jiOI9o5j2nUcx6x1HMcTubmzj2jXMbG/W1HMc33Cnju6CmX2qdoypgMwMqryinCKc80rryDUpWKP6pXwinxSvwFNBT88SnEp8oNE0TSpcBTZXSvQKeAp0VtXhFNhToKZmSm0empTSNsUtKTAYTEWKl0FOxbS5hTsWkvoDE+flPKYDAZZYrFYjEZSylgMBkZGJYlkyeO/uFPTfAU0FP0FPsFX0FP9hTUL8i/GAAAAGC5ub/VVVVVVVVVVVVVVVVVVVRVU3TGMYxjGMYxjHDH/x2aTSaTSaTSaTSaTSaTSaTSaTddXTSzTmJpObpw4cOHDhw4cOHDhzMMyzP2g/gu5IpwoSBVnlx+A";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/sw/iosswrel/ps5012/prod_eol_notice0900aecd8011131b.html";
data[i] = "QlpoMzFBWSZTWYjmo6sABKifgABnfuAQAAAEOLuIEFADmdjG9jMsPANT1VH+/VVEwIGCZBtVP/VVQAaAA0CT1VU00aANAGgTVKo9MkzUPSADBSqI00AAAOW22r1IiIiIiIiIiIgAAAAACyr8BXMFagri6ZnXbfz5XLM0000tMwEWgi0EWgi0EW5mZMtBFoItBFoItBFuZmTLQRaCLQRaHtrWtak2rKiIiIiIiIiIiIiIiIiIiIiIiIiIiIiMQREM/gV2BX+CucCt5WyrJWFGFSbUZ4IwhsxRijKrJG1q46rx221eFrW49YAAAAAAAAAAAAAAEIBKq1x1rcNttWAraleCTKVuCuIFekriVoOsCsHZJqCvEFagrURkjZVRmRijOSyqo/QmgjRJeqWJGcS1RL1VR9o3BWE+YnSJlKylYMGSlqWpalqWrhttq8eYAAAAAatpalWtw221ee22rltb8221NWtzABAAgAAAQOltbq221dNttXOqtuf71AAAAAAAAAAAAAbp+piYmJiYkTExMTExCYmJuLjcXG4uMTExMTExImJi/qq2/xdyRThQkIjmo6s=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/sw/iosswrel/ps5012/prod_eol_notice09186a008032d54a.html";
data[i] = "QlpoMzFBWSZTWcCk/dwAAB6fgABnfSAQAABEGCtAECAAkCgAxGmmjQKqp/qRPKbQ1DTEsXOT0VMXrrChDc7MGRcra2dyGDUzPMJwdm5UYPhQrodGhlYoUQuQQ+2kkk4GChY5Kmp0dFDs/i7kinChIYFJ+7g=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/sw/iosswrel/ps5207/prod_bulletin0900aecd803a0ffe.html";
data[i] = "QlpoMzFBWSZTWYNU8MgAA1MbgABnf+AEBD4r3zBAAtpnAHWttjJ/qoD9+qqGgyGQACHtVVTJgAAAAEKqGjTUY9UyADI0CkqgmmhBkNDTRo0zAF4AC/AAuYAu0AXGmu2+PDjy0xvz3wBSAFSIAUgBSAFIAUgBSAFIA02WZm7x5ubuN4M8U1thNbEzGxMbE1sTWxNbE1sTWxMxsbg4qdQroFe4V5BXUK7fBOym6JwTuTwTwTuTvTqnWPiFdqdQrJzCu8K8gV4ctts222222yKyaNVcwrJ8grkFeYVzCuIVgr9y5BXNOgVk9ZZF2hWTBWT3VMnQK+oVwTzCsT1KZNL707qampkyZMmTJkyZMmTJkyZMmTJ5BXOD0U/vtttVVVVVZAC7EcAC9RT6U/EA/SnOnvTU604qeanJTvCudOFZ45u5x//ukkkkkkkkkkux2Uq7gr2CvRyp0g9HGnOnWmU67KE8lO6m5AMCnFTcpliqqqqqquHN3PbOTpYAAAADlg6U8af6nwUynidmNrMtra2aaYnRTuAL/i7kinChIQap4ZA=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/sw/iosswrel/ps5207/prod_eol_notice0900aecd805019ab.html";
data[i] = "QlpoMzFBWSZTWQXZ8E4AAFMbgABnf+AEBD4rXRAwANjQxgAJgACYM1UADQAAATVUTEaamjIaAHqci4l8lyLQuuOXPTbw6ePl10LUsS5RblgXMuG2fDLTbbbbboXLUsMi1LtFwqbXkWHYsOJdS0LuWXEsywLHMsSzbUdDaJW0JKRtD4bRlMAAAAAAHYuZYlqXcv0ty3L5LcvwtS/S/C4FkW5YlkXuX8W5f4u5IpwoSALs+CcA";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/sw/wirelssw/ps4341/prod_eol_notice0900aecd801e8d0e.html";
data[i] = "QlpoMzFBWSZTWSTOPJcAAXcfgABnf+AQAAAUOGsIEDABhgRCQqU0/9KmjUGAago0NAAAAFKSKaZPUBoGgogWwgXsQLBAvkQLjw15c9vrW23rmZmZmW222222222225mZlEC1EC3EC0Iv5Fui5ItqLhbLieHE1rXC71wuc8kXii6EXsi0i0i9y9EW6LtDEWy3ReaLS6IuSLuRbotxO0MXNFi0GFiLqi0tkXwi0v0X2RfS6LFixYsWLGMWLFixYsWLki6mkCqAOQgTQHTptJJJJJJJJJJPYgWmmkkkkkISSSSEm4C4CBMQLcQLeNttttttttttpttttttttsbbf8Rf4u5IpwoSBJnHkuA=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/sw/wirelssw/ps4341/prod_eol_notice0900aecd804b5519.html";
data[i] = "QlpoMzFBWSZTWdk9TiwAASafgABnfeABEADkGGsIEDABgGAIoTRKPI1PSAAUAA0AAAVNVKCY0TTAaNTbKhuPAB5IH4qHmqGyoc4427dYxi6m7q8XU31V5mbzU5zV5mbATZUP1UPCofyoWKh3HuAbIG/DvQZ3C2eM2VeW8BgMPdUOyoUKhCoYQNaiI1MzNIFBRQcoHSB4VDpUIFQ+xTWTURGwqFUUHKoaVCxUNKhm4iIiN1Tg4IfeHJuTcbY4DgPHbHQzmw5mz6ckkkRERERERFRERy2xbY/mHltibOf9qVFVVfm2OOKpRKl0M69sW2Om2PziqqVKlSqlVUq/+2P0XckU4UJDZPU4sA==";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/sw/wirelssw/ps873/prod_eol_notice0900aecd804cd0af.html";
data[i] = "QlpoMzFBWSZTWb706PwAAMwbgABnf+AgJBirCBAwAQwMR6qA36qDQAAVqf+qoAAAAJqlU8oep6aRpoaZCEFwQeBAhBaEGl+EpYzyzVVVVVdtvMm5PBPkn8TeJuT14cNXs83Dhw2vcnMm0TCbzqT4JhOhOpPImr3iY3J6E0JqTVsTGhMYTGEyV2Jk/SeFciYrtE7PZjGMYxjGMYxjGMdSYTkTmTpK7kxXiVoTCeCad9PIAAAkfREo/F3JFOFCQvvTo/A=";

i++;
oses[i] = "IOS";
urls[i] = "http://www.cisco.com/en/US/products/sw/wirelssw/ps873/prod_eol_notice0900aecd80581e36.html";
data[i] = "QlpoMzFBWSZTWR9FPjAAAMwbgABnf+AgJBirCBAwAQwMR6qA36qDQAAVqf+qoAAAAJqlTQno1MjQaPUIQXBB4ECEFoQaX4SljPLNVVVVV115E6k3JqT+JzJwJ0J6bNnF0cmzZq1uxPUmsTwTaaE7k0J7E8E4E5O8THUnMmhOJOLUmNCYwmMJg1JjyTJ+E3leYn26MYxjGMYxjGMYxj4JhNidie8r9Jit5WhMJuTTecAAASPoiUfi7kinChID6KfGAA==";

i++;
oses[i] = "IOS-XE";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/routers/ps10912/ps11610/end_of_life_notice_c51-726190.html";
data[i] = "QlpoMzFBWSZTWURx014AAAubgARne+AIDwABAAQgACGpkDUYnpP1J6hRoyBo0yNEc4zbOKO4PLA7DIjfbEzVlWYWh5HVe4vqPxdyRThQkERx014=";

i++;
oses[i] = "IOS-XE";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/routers/ps10912/ps11610/end_of_life_notice_c51-726194.html";
data[i] = "QlpoMzFBWSZTWVceKhkAAAubgARneOAIDwABAAQgADFMJpoDTEGqep6NT0MpsmhPGmRtWe4iUEbCkS82Dm6+mCO0tWEzXz10XckU4UJBXHioZA==";

i++;
oses[i] = "IOS-XE";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/routers/ps10912/ps11610/end_of_life_notice_c51-727606.html";
data[i] = "QlpoMzFBWSZTWVe07hoAAAsbgARneOAIDwABAAQgACGoZNAyGmhTCaaA0xJt3SoujbY66AuBLD3AZPS9yMVq+IyhRZY+LuSKcKEgr2ncNA==";

i++;
oses[i] = "IOS-XE";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/routers/ps10912/ps11610/end_of_life_notice_c51-728171.html";
data[i] = "QlpoMzFBWSZTWRQbWYMAAAybgARnfOAIDwABAAQgADFA00MjJiDVNppkmyJtJ6U1DOjs9tFHEEbVAQuP9gjO9Sqccn1cSuZ6LuSKcKEgKDazBg==";

i++;
oses[i] = "IOS-XE";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/routers/ps9343/end_of_life_c51-570651.html";
data[i] = "QlpoMzFBWSZTWf6EQEUAAA0bgARnemAADwABAAQgADFMmJkGRg1MI0GjRoWYW6ZMG4hO7MrDYRy55ArELMwiVX04efi7kinChIf0IgIo";

i++;
oses[i] = "IOS-XE";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/routers/ps9343/end_of_life_notice_c51-519525.html";
data[i] = "QlpoMzFBWSZTWZ0kccAAAA6bgARndCAADwABAAQgACInkjTRpo0KGmmAAPN3VAIMSeyQyTZRwkeCoxYdp0inivi7kinChITpI44A";

i++;
oses[i] = "IOS-XE";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/routers/ps9343/end_of_life_notice_c51-585627.html";
data[i] = "QlpoMzFBWSZTWbrzTqcAAA2bgARnfqAADwABAAQgACImEGmmjRoUwmmgNMQcwmGYnFyg+8IbByh7FfGF0qFyCJVPSup+LuSKcKEhdeadTg==";

i++;
oses[i] = "IOS-XE";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/routers/ps9343/end_of_life_notice_c51-636700.html";
data[i] = "QlpoMzFBWSZTWfmm6+gAABobgARneWAIDwABAAQgAEgqqehBoxNAFVQMQMTNSF2VFa4dJJrsMoU8RqjY7JTYSMvW5JpRNMow1Q6SVQ7VQ/F3JFOFCQ+abr6A";

i++;
oses[i] = "IOS-XE";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/routers/ps9343/end_of_life_notice_c51-645778.html";
data[i] = "QlpoMzFBWSZTWaVFqgcAAA6bgARneeAIDwABAAQgACGphTNA0nqbUKBpoZGTEJ4Vr4N9rHPPiXjAgiOYT3qhLVqIOWPs33P4u5IpwoSFKi1QOA==";

i++;
oses[i] = "IOS-XE";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/routers/ps9343/end_of_life_notice_c51-708773.html";
data[i] = "QlpoMzFBWSZTWYWQyCIAABkbgARneuAIDwABAAQgAEgqqek00aDJoAqpNDIGIPUhZhNWt3CSFlzCfiNUULkrIO3qjQ1KsmahV49Q4UXQ5WQ/F3JFOFCQhZDIIg==";

i++;
oses[i] = "IOS-XE";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/routers/ps9343/end_of_life_notice_c51-709635.html";
data[i] = "QlpoMzFBWSZTWUx/okAAABwbgARneWAIDwABAAQgAEBVU9CDQ0aZCmE00BpiQsuorWzpJ2moXU+RNHhuQlosg4YTNmrdDZN6uyqowy5WZfi7kinChIJj/RIA";

i++;
oses[i] = "IOS-XE";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/routers/ps9343/end_of_life_notice_c51-717501.html";
data[i] = "QlpoMzFBWSZTWQxuf78AABkbgARnfGAIDwABAAQgAEgqqemo0aGjQBVUHqNBk0PSF2Ga1ruFHKUGE+Iqip0Uug1epIbtjRRmohd6l0h+l2slgXckU4UJAMbn+/A=";

i++;
oses[i] = "IOS-XE";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/routers/ps9343/end_of_life_notice_c51-722396.html";
data[i] = "QlpoMzFBWSZTWTZA0xQAACcbgARneWAIDwABAAQgAFCmE00BpiEfqkQ1NqbU2jUlhlsvzfpVVR0woy28TZNoT2iPin5J6pDhus3RFVWX1py4etLsNP4u5IpwoSBsgaYo";

i++;
oses[i] = "IOS-XE";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/routers/ps9343/end_of_life_notice_c51-727629.html";
data[i] = "QlpoMzFBWSZTWQ39V3oAACWbgARneOAIDwABAAQgAFCmE00BpiEfqlMjRppHpPUl4yqv1fCijDx8hlX1PKbQnMOW31J+bQq4Ssso4hV6u0u3UaXYafxdyRThQkA39V3o";

i++;
oses[i] = "IOS-XE";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/routers/ps9343/end_of_life_notice_c51-729046.html";
data[i] = "QlpoMzFBWSZTWYFqPMQAAA2bgARnfKAIDwABAAQgADFMJpoDTEGphTag8TSehRS9v8Zy4pdkkhggghr9B0GyyFW78V79i+C7kinChIQLUeYg";

i++;
oses[i] = "IOS-XE";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/routers/ps9343/eol_c51_519451.html";
data[i] = "QlpoMzFBWSZTWUR5MJ8AAA2bgARndiAADwABAAQgACInlDQ000aFNMjExMQYi2WYuXtF+jSpCJUcPgUUqKdnLPOnn4u5IpwoSCI8mE+A";

i++;
oses[i] = "IOS-XE";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/routers/ps9343/eol_c51_587625.html";
data[i] = "QlpoMzFBWSZTWeP2nR0AAA4bgARneyAADwABAAQgADFMmJkGRg1NlTCZo1NqNqPMLJD6EL5FqjhCfgPUFdqteJOOz68/i7kinChIcftOjoA=";

i++;
oses[i] = "IOS-XE";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/routers/ps9343/eol_c51-683581.html";
data[i] = "QlpoMzFBWSZTWckKdxEAABwbgARneOAIDwABAAQgAEgqqek0GjajQBVSaaZBkG1ISwqtaXKiEqmFfEZo6NSFMkoO2VVDYs1VerIaKMocLofi7kinChIZIU7iIA==";

i++;
oses[i] = "IOS-XE";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/routers/ps9343/eol_c51-698050.html";
data[i] = "QlpoMzFBWSZTWQK7DBUAAA0bgARnfKAADwABAAQgACImmJpoaZNCmTEyDIwWg873fjnBHIwoRYujzxAqAijaaY3pnr4u5IpwoSAFdhgq";

i++;
oses[i] = "IOS-XE";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/routers/ps9343/eos-eol-notice-c51-730604.html";
data[i] = "QlpoMzFBWSZTWRdKHnUAAAwbgARnfaAIDwABAAQgACGp6jQAGjQoGmhkZMQ6VI6vbO14OyGwpoSvsBJpEEdLUTDVy3xdyRThQkBdKHnU";

i++;
oses[i] = "IOS-XE";
urls[i] = "http://www.cisco.com/en/US/prod/collateral/routers/ps10912/ps11610/end_of_life_notice_c51-711402.html";
data[i] = "QlpoMzFBWSZTWczNb4UAAA0bgARnemAIDwABAAQgADFMJpoDTEGppoZBo0aEz5zYsG2g/dhA6gyCp7godVKdH7F64hGj4u5IpwoSGZmt8KA=";

i++;
oses[i] = "IOS-XR";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/iosswrel/ps8803/ps5845/end_of_life_notice_c51-492041.html";
data[i] = "QlpoMzFBWSZTWQAdb6sAAAwbgARnfiAADwABAAQgACGo0aMRpo0KZMTIMjK6i5qzO6CO4HBlCBF5hixnSJ8byu5+LuSKcKEgADrfVg==";

i++;
oses[i] = "IOS-XR";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/iosswrel/ps8803/ps5845/end_of_life_notice_c51-498620.html";
data[i] = "QlpoMzFBWSZTWTmKqiIAAAsbgARnfSAADwABAAQgADFMmJkGRg1NGjINMmhbc7romZA/YQdCmXtAxiK3pErZpzyfi7kinChIHMVVEQA=";

i++;
oses[i] = "IOS-XR";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/iosswrel/ps8803/ps5845/end_of_life_notice_c51-627836.html";
data[i] = "QlpoMzFBWSZTWdJ6sz4AAAwbgARnfSAADwABAAQgADFMmJkGRg1DEaaNNGldwaK1WdxBduOCDso8wLBhC7KpE53PxdyRThQkNJ6sz4A=";

i++;
oses[i] = "IOS-XR";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/iosswrel/ps8803/ps5845/end_of_life_notice_c51-663255.html";
data[i] = "QlpoMzFBWSZTWVoqGQcAAAwbgARnfKAADwABAAQgACImjJpk0aZCmTEyDIwcwR6U4fHLv4SAQ6lpVgMgQopjml7XxdyRThQkFoqGQcA=";

i++;
oses[i] = "IOS-XR";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/iosswrel/ps8803/ps5845/end_of_life_notice_c51-714709.html";
data[i] = "QlpoMzFBWSZTWWRZ+QwAAAubgARnfOAADwABAAQgACGpk00aAMhTCaaA0xCt1KZRsaHS9QaCkSm7Dk6mFHI8jw24+LuSKcKEgyLPyGA=";

i++;
oses[i] = "IOS-XR";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/iosswrel/ps8803/ps5845/end_of_life_notice_c51-716197.html";
data[i] = "QlpoMzFBWSZTWaPGi9MAAAubgARnfGAADwABAAQgADFMmJkGRg1NNNNNDTRoSxZHznTwg7ccFyUF5hs1qEET49Szz8XckU4UJCjxovTA";

i++;
oses[i] = "IOS-XR";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/iosswrel/ps8803/ps5845/eol_c51_596913.html";
data[i] = "QlpoMzFBWSZTWbAHl2EAAAqbgARnemAADwABAAQgADFMmJkGRg1NMmjI0GhZ4ljdhqo52DFoBeQMECnVRue69LxPxdyRThQkLAHl2EA=";

i++;
oses[i] = "IOS-XR";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/routers/ps167/prod_end-of-life_notice0900aecd8055b332_ps5845_Products_End-of-Life_Notice.html";
data[i] = "QlpoMzFBWSZTWVTMZrYAAAsbgARnfOAADwABAAQgADFMJpoDTEGpoaNBoYhJ6ppUi35QrGFFwT9yKCxyt2MM8Z5HxdyRThQkFTMZrYA=";

i++;
oses[i] = "IOS-XR";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/routers/ps5763/end_of_life_notice_c51-464994_ps5845_Products_End-of-Life_Notice.html";
data[i] = "QlpoMzFBWSZTWbyiXQ0AABYbgARnfGAADwABAAQgAEBVU9JiGI0aFMmJkGRkLWyoqsuuw4ZmR6kUTeEknzk6KSQcIqy05VfNOmGn4u5IpwoSF5RLoaA=";

i++;
oses[i] = "NX-OS";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/ps4159/ps6409/ps5989/end_of_life_c51-574063.html";
data[i] = "QlpoMzFBWSZTWfSBpdkAAA4bgARnfqAADwABAAQgAFRTCaaA0xBKgNBPU9BpHGxa/ZD8pLm4MgwVOsWmJEnoFOP2QKjv8XckU4UJD0gaXZA=";

i++;
oses[i] = "NX-OS";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/ps4159/ps6409/ps5989/ps6039/end_of_life_c51-565774.html";
data[i] = "QlpoMzFBWSZTWW5HBygAAA6bgARndyAADwABAAQgAEhKmg0mMpjQpkxMgyMT7Zq1MBRGObk6jioJbriyqT/BjkdmDLEULuSKcKEg3I4OUA==";

i++;
oses[i] = "NX-OS";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/ps4159/ps6409/ps5989/ps9898/eol_c51-698206.html";
data[i] = "QlpoMzFBWSZTWYua2scAAA2bgARnfKAADwABAAQgAEhKmibSbTRpPUKZMTIMjEaDN2YEenYpY2cUT7PC57ZTyAc7K1B1maF3JFOFCQi5raxw";

i++;
oses[i] = "NX-OS";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/switches/ps9441/ps9402/end_of_life_c51_605635.html";
data[i] = "QlpoMzFBWSZTWRKansoAAA+bgARnfqAADwABAAQgAFRTCaaA0xBKp6amnqNGwiI0j3xgJR2Kri3REKNYTUCnd1aQc1vftB3Hp+LuSKcKEgJTU9lA";

i++;
oses[i] = "NX-OS";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/switches/ps9441/ps9402/eol_c51-693308.html";
data[i] = "QlpoMzFBWSZTWRrcnHMAAA6bgARne+AADwABAAQgAFRQNNDIyYglQZJkZPTQRo5+vqA8mYvrUFJmaktvknVREi4MX5vzgd0sfF3JFOFCQGtyccw=";

i++;
oses[i] = "NX-OS";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/switches/ps9441/ps9402/eol_c51-695349.html";
data[i] = "QlpoMzFBWSZTWReN4pEAAA6bgARnfOAADwABAAQgAFRTCaaA0xBKnqnqeo0No0IqyQ7eAoUrOacDwJYWppgarMpC5ben2F1afi7kinChIC8bxSI=";

i++;
oses[i] = "NX-OS";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/switches/ps9441/ps9402/eol_c51-709991.html";
data[i] = "QlpoMzFBWSZTWVyl8MAAAA6bgARnfqAADwABAAQgAFRTCaaA0xBKFGTCbTQL9BeVrBDOprSMPNUXO/0ySai+QDl+bnwHo0/F3JFOFCQXKXwwAA==";

i++;
oses[i] = "NX-OS";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/switches/ps9441/ps9402/eol__C51-726666.html";
data[i] = "QlpoMzFBWSZTWchCVrkAAA6bgARneeAADwABAAQgAFRTCaaA0xBKUeptINPU/SJtCJt3wCx82KprjtcjMity7wyCTOtRQT0p+LuSKcKEhkIStcg=";

i++;
oses[i] = "NX-OS";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/switches/ps9441/ps9670/eol_c51-704909.html";
data[i] = "QlpoMzFBWSZTWfcKkQ8AAD4bgARnfqAADwABAAQgAHBTCaaA0xAqqeiaGgxGkG26MCRQqahhBYkmXO3p6aVJlBBchUggfFC7RqcEkyhgLD7mIyZNiwWOS5k/F3JFOFCQ9wqRDw==";

i++;
oses[i] = "NX-OS";
urls[i] = "http://www.cisco.com/en/US/customer/prod/collateral/switches/ps9441/ps9902/eol_C51-716648.html";
data[i] = "QlpoMzFBWSZTWVgyAJ4AAA6bgARnfmABDwABAAQgAFRQNNDIyYg1T8qempoHimIVQ+VR53MXssS/AkIwkXywdrRdmNLRwGzrpI+LuSKcKEgsGQBPAA==";

i++;
oses[i] = "PIX";
urls[i] = "http://www.cisco.com/c/en/us/support/security/pix-firewall-software-version-2-7/model.html";
data[i] = "QlpoMzFBWSZTWU574xkAAAiagARneOAADwAEIAAhqPUyGmhpoU0yMTExJcorBtlxEleqT0ZQVvakBIhk9mfi7kinChIJz3xjIA==";

i++;
oses[i] = "PIX";
urls[i] = "http://www.cisco.com/c/en/us/support/security/pix-firewall-software-version-3-0/model.html";
data[i] = "QlpoMzFBWSZTWf1gwuAAAAsagARneWAADwAEIAAxTTIxMTEGpk9Q0Gmmk4U2YGOBzuXXCUQoGFlEA97B80/F3JFOFCQ/WDC4AA==";

i++;
oses[i] = "PIX";
urls[i] = "http://www.cisco.com/c/en/us/products/collateral/security/pix-500-series-security-appliances/prod_end-of-life_notice0900aecd805753f3.html";
data[i] = "QlpoMzFBWSZTWRa5LEIAAAqagARnfGAADwAEIAAxTTIxMTEGppppiGRpS3wnHTs8gRR5MBnMiCEFDzPceavi7kinChIC1yWIQA==";

i++;
oses[i] = "PIX";
urls[i] = "http://www.cisco.com/c/en/us/products/collateral/security/pix-500-series-security-appliances/prod_end-of-life_notice0900aecd8056d2fc.html";
data[i] = "QlpoMzFBWSZTWS0qT2EAAAmagARndmAADwAEIAAiJkyM1BpoU0yMTExKdFbSwOT3tNibQZC5mwJASTIXz18XckU4UJAtKk9h";

i++;
oses[i] = "PIX";
urls[i] = "http://www.cisco.com/c/en/us/products/collateral/security/pix-500-series-security-appliances/prod_end-of-life_notice0900aecd8056d2c5.html";
data[i] = "QlpoMzFBWSZTWXYSSngAAAuagARnfSAADwAEIAAxTTIxMTEEqaGg0NGkZnVeMxrh2KjCOGEyUVAd+39ePi7kinChIOwklPA=";

i++;
oses[i] = "PIX";
urls[i] = "http://www.cisco.com/c/en/us/products/collateral/security/pix-500-series-security-appliances/prod_end-of-life_notice0900aecd8056d2b1.html";
data[i] = "QlpoMzFBWSZTWcP6kEAAAAmagARnfCAADwAEIAAhqbUyaaGjQoaaYAK0VaBCDm+0ZGBiyEOULOGmer7NfF3JFOFCQw/qQQA=";

i++;
oses[i] = "PIX";
urls[i] = "http://www.cisco.com/c/en/us/products/collateral/security/pix-500-series-security-appliances/prod_end-of-life_notice0900aecd8056d289.html";
data[i] = "QlpoMzFBWSZTWQminaIAAAoagARndSAADwAEIAAxQ00wADUY1Bk0aU6MYd4CjtKGEgoMhbEsLzPO+3XxdyRThQkAminaIA==";

i++;
oses[i] = "PIX";
urls[i] = "http://www.cisco.com/c/en/us/products/collateral/security/pix-500-series-security-appliances/prod_end-of-life_notice0900aecd805753e1.html";
data[i] = "QlpoMzFBWSZTWX2mt7wAAAsagARnemAADwAEIAAxTTIxMTEGowho0yaVkkXjLN36HpBAuY0wIGgUhEZnzV8XckU4UJB9pre8";

i++;
oses[i] = "PIX";
urls[i] = "http://www.cisco.com/c/en/us/products/collateral/security/pix-500-series-security-appliances/prod_end-of-life_notice0900aecd8056d273.html";
data[i] = "QlpoMzFBWSZTWfi8MoQAAAqagARncmAADwAEIAAxQ00wACVGmTQNGk4RW0uaneEwMRR0MFhRlIh++zPxdyRThQkPi8MoQA==";

i++;
oses[i] = "PIX";
urls[i] = "http://www.cisco.com/c/en/us/support/security/pix-firewall-software-version-5-2/model.html";
data[i] = "QlpoMzFBWSZTWTvBL1cAAAoagARnfuAADwAEIAAhojQaBppoUwmmgNMSFklJqud8DxYVHAxkuAaVMmbr+vHxdyRThQkDvBL1cA==";

i++;
oses[i] = "PIX";
urls[i] = "http://www.cisco.com/c/en/us/products/collateral/security/pix-500-series-security-appliances/prod_end-of-life_notice0900aecd80565c3b.html";
data[i] = "QlpoMzFBWSZTWVAdRuoAAAoagARnfqAADwAEIAAhpMINDQ0KZMTIMjJc1bbvktdlAogWMrhCNmERzvsT8XckU4UJBQHUbqA=";

i++;
oses[i] = "PIX";
urls[i] = "http://www.cisco.com/c/en/us/products/collateral/security/pix-500-series-security-appliances/prod_end-of-life_notice0900aecd800f8954.html";
data[i] = "QlpoMzFBWSZTWd6X30QAAAmagARndaAADwAEIAAxTTIxMTEGoyGTQPSSUtfkRvqgz4SwfAIWAgRmCGxl96g/F3JFOFCQ3pffRA==";

i++;
oses[i] = "PIX";
urls[i] = "http://www.cisco.com/c/en/us/products/collateral/security/pix-500-series-security-appliances/end_of_life_notice_for_cisco_pix_security_app_software.html";
data[i] = "QlpoMzFBWSZTWdfGRXcAAAmagARneeAADwAEIAAhqaNNGQ000KZMTIMjJWp34zatDiWDjBlVQQVDCAnfseafi7kinChIa+Miu4A=";

i++;
oses[i] = "PIX";
urls[i] = "http://www.cisco.com/c/en/us/products/collateral/security/pix-500-series-security-appliances/end_of_life_notice_for_cisco_pix_sec_app_v63.html";
data[i] = "QlpoMzFBWSZTWU0VxhgAAAmagARneeAADwAEIAAhqBkPUZDQpkxMgyMg0sjErVh2HDi6TyKyytgom7874x8XckU4UJBNFcYY";

i++;
oses[i] = "PIX";
urls[i] = "http://www.cisco.com/c/en/us/products/collateral/security/pix-500-series-security-appliances/end_of_life_notice_for_cisco_pix_sec_app_v7.html";
data[i] = "QlpoMzFBWSZTWbA3XvsAAAoagARneOAADwAEIAAhqMIaNMmhTTIxMTErJIrssunQ9QCGUuwMMYXFyiNT7dfF3JFOFCQsDde+wA==";

i++;
oses[i] = "PIX";
urls[i] = "http://www.cisco.com/c/en/us/products/collateral/security/pix-500-series-security-appliances/end_of_life_notice_for_cisco_pix_sec_app_sw_71.html";
data[i] = "QlpoMzFBWSZTWSrk3ZQAAAoagARneOAADwAEIAAhqYIyDRoU0yMTExKc1baxpO8FSJGCU4CCEDXI5l++zXxdyRThQkCrk3ZQ";

i++;
oses[i] = "PIX";
urls[i] = "http://www.cisco.com/c/en/us/products/collateral/security/pix-500-series-security-appliances/end_of_life_notice_for_cisco_pix_sec_app_software_v72.html";
data[i] = "QlpoMzFBWSZTWYFRRZIAAAmagARneOAADwAEIAAhqYIZDRoU0yMTExKc1bcRpO8FQJGFI3BB0DXI5nPfRXxdyRThQkIFRRZI";

i++;
oses[i] = "PIX";
urls[i] = "http://www.cisco.com/c/en/us/products/collateral/security/pix-500-series-security-appliances/end_of_life_notice_for_cisco_pix_sec_app_sw_v8.html";
data[i] = "QlpoMzFBWSZTWagpfbEAAAoagARneOAADwAEIAAhqZMmmjTRoU0yMTExKY0WHXsJwRUgwyE4uHuFBYmX77VfF3JFOFCQqCl9sQ==";

m_index = i;

# #####################################
# Attempt to determine if any exact matches are possible
# #####################################
for (i=0; i<=m_index; i++)
{
  # Is the OS one that we are interested in?
  if (
    (os_type == "IOS" && oses[i] != "IOS") ||
    (os_type == "IOS-XE" && oses[i] != "IOS-XE") ||
    (os_type == "IOS-XR" && oses[i] != "IOS-XR") ||
    (os_type == "NX-OS" && oses[i] != "NX-OS") ||
    (os_type == "PIX" && oses[i] != "PIX")
  ) continue;

  search_pattern = "^0," + regexify(str:os_ver) + ",,";
  if (!isnull(model)) search_pattern = "^0," + regexify(str:os_ver) + "," + regexify(str:model);

  # un b64 .. un bzip2
  res = base64_decode(str:data[i]);
  res = bzip2_decompress(data:res);
  res = ereg_replace(pattern:"\\n", replace:'\n', string:res);

  eol_list = egrep(pattern:search_pattern, string:res);
  if (strlen(eol_list))
  {
    exact_check(eol_list:eol_list, ostype:os_type, url:urls[i]);
  }
}

# #####################################
# Attempt to determine if any non-exact matches are possible
# #####################################
n = m_index;

for (i=0; i<=n; i++)
{
  # Is the OS one that we are interested in?
  if (
    (os_type == "IOS" && oses[i] != "IOS") ||
    (os_type == "IOS-XE" && oses[i] != "IOS-XE") ||
    (os_type == "IOS-XR" && oses[i] != "IOS-XR") ||
    (os_type == "NX-OS" && oses[i] != "NX-OS") ||
    (os_type == "PIX" && oses[i] != "PIX")
  ) continue;

  search_pattern = "^(1|2),";

  # un b64 .. un bzip2
  res = base64_decode(str:data[i]);
  res = bzip2_decompress(data:res);
  res = ereg_replace(pattern:"\\n", replace:'\n', string:res);

  eol_list = egrep(pattern:search_pattern, string:res);
  if (strlen(eol_list))
  {
    regex_check(eol_list:eol_list, ostype:os_type, version:os_ver, url:urls[i]);
  }
}

#os not eol
if (!isnull(model))
  exit(0, "The Cisco "+os_type+" version ["+os_ver+"] hardware model ["+model+"] is currently supported.");
exit(0, "The Cisco "+os_type+" version ["+os_ver+"] is currently supported.");
