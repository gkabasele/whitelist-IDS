module CheckActivityModule;

export {
    const check_interval = 5sec;
    global regular_check: event(c: connection);
    }

event CheckActivityModule::regular_check(c: connection)
    {
        if (c$history == "Sh")
            {
            SumStats::observe("conn attempted",
                              SumStats::Key($host=c$id$resp_h),
                              SumStats::Observation($num=1));
            schedule check_interval {CheckActivityModule::regular_check(c)};
            }
    }

