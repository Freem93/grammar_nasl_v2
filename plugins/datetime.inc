#TRUSTED 43661d622c2142ac864cf86d94218197e3a3e2f5cbf59bf9781470200b5fdbb02deacf663a0323fdae631a3a4cd130c8316c3b131f88d19bab418f4abffcd683502f460087af79d91b33cb0bac710bb92f5af9e1702c35d441e7972c6de4b31d628fc29835e7c9d623424bf1bb7e36c1eec3e69915b337098f9437851bac1737cb7975b299b744819aad1ad0588fe8780efc3103b761e1de7c2bf19a8d7a3a853d952b57ef2834fc340bd95649f8690c9e163d49944784470d95d620ef0c81d2b2e0d42abd961df21e953ec84efc681bda25a2ceb38aa152f10f0381050ce7191ce64b7d1a88a90017a951eb240198276e6d4bdbab32d28c7b18f7a8eba4a4e0befe7d744c51c386e2a59b24015b8db5e04d761cda8b54359011e53b331de24865bd43494b4534d138389cfc7632838b63069e301e1b416ff9f1086778a2108c59f8331830a2068c4f748d6c8ec0b358e6af0ff8388c8f0454967ad11b852ebefd5eabfb3da44b9f7ec8bf8a3e342b9e8bb602680c66cb958616ea5a58658b2418efae4acabfbdab5a519db55b6988d602ccb39f8b77ba2a0677af9376494d3662764f7757b07fd8777c461becfd2a5490561556b4253e9fdb023f083cdcd2ea573264054aeffda5ac94b168792b2abbc2fe5b69cb41a836980beeda4e2c849090692eff2f4c9ebd438fcb2e7fc0f3c94fdb60f529e3bb10fccc80db1134333e
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# datetime.inc
# Revision: 1.11
#

global_var _months_num, _months_str;

_months_num = make_list(
  "January", "February", "March", "April", "May", "June", "July",
  "August", "September", "October", "November", "December"
);

_months_str = make_array(
  "January", 0,
  "February", 1,
  "March", 2,
  "April", 3,
  "May", 4,
  "June", 5,
  "July", 6,
  "August", 7,
  "September", 8,
  "October", 9,
  "November", 10,
  "December", 11
);

_weekday_num = make_list(
  "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
  "Saturday"
);

### FILETIME Constants ###
global_var FILETIME_TICK, FILETIME_BIAS;
FILETIME_TICK = 10000000;
FILETIME_BIAS = "11644473600";

##
# Returns the name associated with a month given its number.
#
# @anonparam num The number representing the month.
#
# @param base The base at which the months are numbered, default is 0.
# @param short Whether to return the three-letter short version of the
#              month name, false by default.
#
# @return The name associated with the specified number.
##
function month_name_by_num(base, short)
{
  local_var name, num;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
    return NULL;

  # Set defaults.
  if (isnull(base))
    base = 0;
  if (isnull(short))
    short = FALSE;

  num = _FCT_ANON_ARGS[0];

  # Find the specified month.
  name = _months_num[num - base];
  if (isnull(name))
    return NULL;

  # Shorten if requested.
  if (short)
    name = substr(name, 0, 2);

  return name;
}

##
# Returns the number associated with a month given its name.
#
# @anonparam name The full, capitalized name of the month, in English.
#
# @param base The base at which the months are numbered, default is 0.
#
# @return The number associated with the named month.
##
function month_num_by_name(base)
{
  local_var month, name;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
    return NULL;

  # Set defaults.
  if (isnull(base))
    base = 0;

  name = _FCT_ANON_ARGS[0];

  # Try and find a month that matches the name or abbreviation given.
  foreach month (keys(_months_str))
  {
    if (month =~ "^" + name)
      return base + _months_str[month];
  }

  return NULL;
}

##
# Compare two dates.
#
# @anonparam then A date in "M D H:M:S Y TZ" format.
#
# @param base_date Optional base unix timestamp to compare against. Default is now.
#
# @return Returns an integer indicating the difference between the
#         dates.
##
function date_cmp(base_date)
{
  local_var now, then, time;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
    return NULL;

  then = _FCT_ANON_ARGS[0];

  then = split(then, sep:" ", keep:FALSE);
  now = localtime(utc:1);
  if(!isnull(base_date)) now = localtime(base_date, utc:1);
  # If the year is earlier than the year this function was updated,
  # then the clock is wrong.
  if (now["year"] < 2012)
    return NULL;

  if (then[3] != now["year"])
    return int(now["year"]) - int(then[3]);

  if (month_num_by_name(then[0], base:1) != now["mon"])
    return int(now["mon"]) - month_num_by_name(then[0], base:1);

  if (int(then[1]) != now["mday"])
    return int(now["mday"]) - int(then[1]);

  time = split(then[2], sep:":", keep:FALSE);

  if (int(time[0]) != now["hour"])
    return int(now["hour"]) - int(time[0]);

  if (int(time[1]) != now["min"])
    return int(now["min"]) - int(time[1]);

  if (int(time[2]) != now["sec"])
    return int(now["sec"]) - int(time[2]);

  return 0;
}

##
# Returns the name associated with a day of the week given its number.
#
# @anonparam num The number representing the day of the week.
#
# @param base The base at which the days of the week are numbered,
#             default is 0.
# @param short Whether to return the three-letter short version of the
#              day of the week's name, false by default.
#
# @return The name associated with the specified number.
##
function weekday_name_by_num(base, short)
{
  local_var name, num;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
    return NULL;

  # Set defaults.
  if (isnull(base))
    base = 0;
  if (isnull(short))
    short = FALSE;

  num = _FCT_ANON_ARGS[0];

  # Find the specified weekday.
  name = _weekday_num[num - base];
  if (isnull(name))
    return NULL;

  # Shorten if requested.
  if (short)
    name = substr(name, 0, 2);

  return name;
}

##
# Prefixes an integer as necessary to be a certain size.
#
# @anonparam num The number to be formatted.
#
# @param prefix The string to prefix the number with, zero by default.
# @param size The minimum length of the string, two by default.
#
# @return The number as a string, prefixed if necessary.
##
function prefix_num(prefix, size)
{
  local_var len, num;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
    return NULL;

  # Set defaults.
  if (isnull(prefix))
    prefix = 0;

  if (isnull(size))
    size = 2;

  num = string(_FCT_ANON_ARGS[0]);
  prefix = string(prefix);

  len = strlen(num);
  if (len < size)
    num = crap(data:prefix, length:size - len) + num;

  return num;
}

##
# Formats a Unix epoch timestamp like strftime(3).
#
# %A is replaced by national representation of the full weekday name.
#
# %a is replaced by national representation of the abbreviated weekday
#    name.
#
# %B is replaced by national representation of the full month name.
#
# %b is replaced by national representation of the abbreviated month
#    name.
#
# %d is replaced by the day of the month as a decimal number (01-31).
#
# %e is replaced by the day of the month as a decimal number (1-31);
#    single digits are preceded by a blank.
#
# %F is equivalent to "%Y-%m-%d".
#
# %H is replaced by the hour (24-hour clock) as a decimal number
#    (00-23).
#
# %I is replaced by the hour (12-hour clock) as a decimal number
#    (01-12).
#
# %k is replaced by the hour (24-hour clock) as a decimal number
#    (0-23); single digits are preceded by a blank.
#
# %l is replaced by the hour (12-hour clock) as a decimal number
#    (1-12); single digits are preceded by a blank.
#
# %M is replaced by the minute as a decimal number (00-59).
#
# %m is replaced by the month as a decimal number (01-12).
#
# %N is equivalent to "%b. %e, %Y at %T GMT"; this is a Nessus
#    extension, not the normal behavior of strftime(3).
#
# %S is replaced by the second as a decimal number (00-60).
#
# %T is equivalent to "%H:%M:%S".
#
# %Y is replaced by the year with century as a decimal number.
#
# %y is replaced by the year without century as a decimal number
#    (00-99).
#
# @anonparam fmt The format string for the output, "%N" by default.
# @anonparam when Either an array (in [builtin#localtime] format), or
#                 a 32-bit epoch timestamp. The current time is used
#                 by default.
#
# @return The formatted version of the time and date.
##
function strftime()
{
  local_var field, fmt, i, len, when;

  # Sanity check parameters.
  len = max_index(_FCT_ANON_ARGS);
  if (len == 0)
  {
    fmt = "%N";
    when = localtime(utc:TRUE);
  }
  else if (len == 1)
  {
    fmt = "%N";
    when = _FCT_ANON_ARGS[0];
  }
  else if (len == 2)
  {
    fmt = _FCT_ANON_ARGS[0];
    when = _FCT_ANON_ARGS[1];
  }
  else
  {
    return NULL;
  }

  if (typeof(when) == "int")
  {
    if ( when < 0 || when >= 2147483647 ) return NULL;
    else when = localtime(when, utc:TRUE);
  }

  # Add in a key that represents the hour on a twelve-hour clock.
  if (when["hour"] == 0)
    when["12hr"] = 12;
  else if (when["hour"] > 12)
    when["12hr"] = when["hour"] - 12;
  else
    when["12hr"] = when["hour"];

  while (TRUE)
  {
    # Find a format specifier.
    field = eregmatch(string:fmt, pattern:"(%[a-zA-Z])");
    if (isnull(field))
      break;
    field = field[1];

    if (field == "%A")
    {
      fmt = str_replace(string:fmt, find:field, replace:weekday_name_by_num(when["wday"], short:FALSE));
    }
    else if (field == "%a")
    {
      fmt = str_replace(string:fmt, find:field, replace:weekday_name_by_num(when["wday"], short:TRUE));
    }
    else if (field == "%B")
    {
      fmt = str_replace(string:fmt, find:field, replace:month_name_by_num(when["mon"], base:1, short:FALSE));
    }
    else if (field == "%b")
    {
      fmt = str_replace(string:fmt, find:field, replace:month_name_by_num(when["mon"], base:1, short:TRUE));
    }
    else if (field == "%d")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["mday"]));
    }
    else if (field == "%e")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["mday"], prefix:" "));
    }
    else if (field == "%F")
    {
      fmt = str_replace(string:fmt, find:field, replace:"%Y-%m-%d");
    }
    else if (field == "%H")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["hour"]));
    }
    else if (field == "%I")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["12hr"]));
    }
    else if (field == "%k")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["hour"], prefix:" "));
    }
    else if (field == "%l")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["12hr"], prefix:" "));
    }
    else if (field == "%M")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["min"]));
    }
    else if (field == "%m")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["mon"]));
    }
    else if (field == "%N")
    {
      fmt = str_replace(string:fmt, find:field, replace:"%b. %e, %Y at %T GMT");
    }
    else if (field == "%S")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["sec"]));
    }
    else if (field == "%T")
    {
      fmt = str_replace(string:fmt, find:field, replace:"%H:%M:%S");
    }
    else if (field == "%Y")
    {
      fmt = str_replace(string:fmt, find:field, replace:when["year"]);
    }
    else if (field == "%y")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["year"] % 100));
    }
    else
    {
      # Remove unrecognized specifiers to prevent infinite loops.
      fmt = str_replace(string:fmt, find:field, replace:"");
    }
  }

  return fmt;
}

##
# Converts a Windows FILETIME value into Unix Epoch time.
#
# @param  string filetime in hex representation
#
# @return int unixtime as integer
##
function filetime_to_unixtime(filetime)
{
  local_var output;

  if (isnull(filetime)) filetime = _FCT_ANON_ARGS[0];
  if (isnull(filetime))
  {
    err_print("filetime_to_unixtime(): missing required arg 'filetime'");
    return -1;
  }

  # Convert input to raw data.
  output = bn_hex2raw(filetime);
  # Divide filetime by FILETIME_TICK (100 ns unless something changed)
  output = bn_div(output, bn_dec2raw(FILETIME_TICK));
  # Subtract FILETIME_BIAS since Windows FILETIME starts in 1601.
  output = bn_sub(output, bn_dec2raw(FILETIME_BIAS));
  # Convert to decimal representation.
  output = bn_raw2dec(output);

  # Return as 32-bit integer.
  return int(output);
}


##
# Converts an ASN1 UTCTIME value into Unix Epoch time.
#
# @param  string UTCTIME in UTCTIME representation
#
# @return int unixtime as integer
##
function utctime_to_unixtime(utctime)
{
  local_var output, year, month, day, hour, minute, second;

  if (isnull(utctime)) utctime = _FCT_ANON_ARGS[0];
  if (isnull(utctime))
  {
    err_print("utctime_to_unixtime(): missing required arg 'utctime'");
    return -1;
  }

  # YYMMDDhhmm[ss]Z
  # 150928230106Z

  year = int(substr(utctime, 0, 1));
  if (year > 50)
    year += 1900;
  else
    year += 2000;

  month = int(substr(utctime, 2, 3));
  day = int(substr(utctime, 4, 5));
  hour = int(substr(utctime, 6, 7));
  minute = int(substr(utctime, 8, 9));
  second = int(substr(utctime, 10, 11));

  output = mktime(
    year:year,
    mon:month,
    mday:day,
    hour:hour,
    min:minute,
    sec:second
  );

  return output;
}
