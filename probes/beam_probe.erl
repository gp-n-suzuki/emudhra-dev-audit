io:format("EMUDHRA_RUNTIME:~s~n", [erlang:system_info(otp_release)]),
lists:foreach(fun(Name) ->
    application:load(Name),
    case application:get_key(Name, vsn) of
        {ok, Version} -> io:format("EMUDHRA_LIB:~s:~s~n", [atom_to_list(Name), Version]);
        _ -> ok
    end
end, [certifi, castore]),
halt().
