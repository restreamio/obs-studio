if(RESTREAM_CLIENTID AND RESTREAM_HASH MATCHES "^(0|[a-fA-F0-9]+)$" AND TARGET OBS::browser-panels)
  target_sources(
    obs-studio
    PRIVATE
      auth-restream.cpp
      auth-restream.hpp
      window-restream-actions.cpp
      window-restream-actions.hpp
  )

  target_enable_feature(obs-studio "Restream API connection" RESTREAM_ENABLED)
else()
  target_disable_feature(obs-studio "Restream API connection")
  set(RESTREAM_CLIENTID "")
  set(RESTREAM_HASH "0")
endif()
