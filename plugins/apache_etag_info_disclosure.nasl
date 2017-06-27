#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88098);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/08/01 15:11:42 $");

  script_cve_id("CVE-2003-1418");
  script_bugtraq_id(6939);
  script_osvdb_id(60395);

  script_name(english:"Apache Server ETag Header Information Disclosure");
  script_summary(english:"Looks for ETag in HTTP headers.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server is affected by an information disclosure
vulnerability due to the ETag header providing sensitive information
that could aid an attacker, such as the inode number of requested
files.");
  script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/docs/2.2/mod/core.html#FileETag");
  script_set_attribute(attribute:"solution", value:
"Modify the HTTP ETag header of the web server to not include file
inodes in the ETag header calculation. Refer to the linked Apache
documentation for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "apache_http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("string.inc");
include("datetime.inc");
include("math64.inc");

port = get_http_port(default:80);
# Make sure this is Apache.
get_kb_item_or_exit('www/'+port+'/apache');

vuln = FALSE;

banner = get_http_banner(port: port, exit_on_fail:TRUE);

etag_header = eregmatch(
  pattern : 'ETag: "([0-9a-zA-F-]+)"',
  string  : banner
);

if (!empty_or_null(etag_header))
{
  etag = split(etag_header[1], sep:"-", keep:FALSE);
  count = max_index(etag);

  # For Apache, the ETag format is INode-Size-MTime
  # This can be modified to display one, two, all, or none of these
  # fields. While the order will remain the same, there is no way
  # to differentiate the INode and MTime fields

  if (count == '3')
  {

    inode = strtol(etag[0], base:16);
    if (inode < 0) inode = NULL;
    size = strtol(etag[1], base:16);
    if (size < 0) size = NULL;

    time = etag[2];
    time_len = strlen(time);

    # Apache 1.x stored the time in a 32-bit value
    if (time_len == 8)
    {
      time_dec = hex2dec(xvalue:time);
      if (time_dec <= 0) mtime = NULL;
      else
        mtime = strftime(time_dec);
    }
    else
    {
      # Apache 2.x
      low_bit = '';
      high_bit = '';

      # Start backwards and split up into two 32-bit values
      for (i=time_len - 1; i>=0; i--)
      {
        if (strlen(low_bit) < 8)
        {
          low_bit += time[i];
        }
        else
        {
          high_bit += time[i];
        }
      }

      # Padding for high bits. We can work with two 32-bit as one 64-bit value
      hbit_len = strlen(high_bit);
      if (hbit_len < 8)
      {
        pad = "00000000";
        for (i=0; i < 8; i++)
        {
          if (hbit_len == i)
            high_bit += pad;
            pad = pad - "0";
        }
      }

      # Since we looped over these in reverse order, restore the HEX value
      # to it's original order
      high_bit =string_reverse(high_bit);
      low_bit = string_reverse(low_bit);

      # Use 64-bit number.  Convert low and high bits to decimal as they were
      # stored as HEX in a string.
      etag_64 = make_int64(
        high : hex2dec(xvalue:high_bit),
        low  : hex2dec(xvalue:low_bit)
      );
      # Divide by 1000000 to get our 32-bit value which we can
      # then convert to epoch time and display
      etag_div  = div64(etag_64, make_int64(low:0x000F4240));
      if (etag_div[0] > 0)
        mtime = strftime(etag_div[0]);
      else mtime = NULL;
    }
  }
  if (!isnull(inode))
  {
    if (report_verbosity > 0)
    {
      report =
        '\nNessus was able to determine that the Apache Server listening on' +
        '\nport ' +port+ ' leaks the servers inode numbers in the ETag HTTP' +
        '\nHeader field : \n' +
        '\n  Source                 : ' + etag_header[0] +
        '\n  Inode number           : ' + inode;

      if (!isnull(size))
      {
        report +=
          '\n  File size              : ' + size + " bytes";
      }
      if (!isnull(mtime))
      {
        report +=
          '\n  File modification time : ' + mtime + '\n';
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
  else
    exit(0, "Nessus was unable to identify an inode number in the ETag HTTP Header from the Apache server on port ", port);
}
else
  exit(0, "The banner from the Apache server on port " + port + " does not include the 'ETag' HTTP Header field.");
