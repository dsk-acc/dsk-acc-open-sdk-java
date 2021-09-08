package com.dsk.acc.openapi.client.core;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

public class AccConverter {

    @SuppressWarnings("unchecked")
    public static <T> Map<String, T> buildMap(AccPair... pairs) {
        Map<String, T> map = new HashMap<String, T>();
        for (int i = 0; i < pairs.length; i++) {
            AccPair pair = pairs[i];
            map.put(pair.key, (T) pair.value);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    public static <T> Map<String, T> merge(Class<T> t, Map<String, ?>... maps) {
        Map<String, T> out = new HashMap<String, T>();
        for (int i = 0; i < maps.length; i++) {
            Map<String, ?> map = maps[i];
            if (null == map) {
                continue;
            }
            Set<? extends Entry<String, ?>> entries = map.entrySet();
            for (Entry<String, ?> entry : entries) {
                if (null != entry.getValue()) {
                    out.put(entry.getKey(), (T) entry.getValue());
                }
            }
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    public static <T> Map<String, T> merge(Class<T> t, Object... maps) {
        Map<String, T> out = new HashMap<String, T>();
        Map<String, ?> map = null;
        for (int i = 0; i < maps.length; i++) {
            if (null == maps[i]) {
                continue;
            }
            if (AccModel.class.isAssignableFrom(maps[i].getClass())) {
                map = AccModel.buildMap((AccModel) maps[i]);
            } else {
                map = (Map<String, T>) maps[i];
            }
            Set<? extends Entry<String, ?>> entries = map.entrySet();
            for (Entry<String, ?> entry : entries) {
                if (null != entry.getValue()) {
                    out.put(entry.getKey(), (T) entry.getValue());
                }
            }
        }
        return out;
    }

}
