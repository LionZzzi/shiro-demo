package com.eric.demo.common;

import lombok.Data;

import java.text.SimpleDateFormat;
import java.util.Date;

@Data
public class Result {

    private boolean ret;

    private String msg;

    private Object data;

    private String time;

    private Result(boolean ret) {
        this.ret = ret;
    }

    public static Result success(Object data, String msg) {
        Result result = new Result(true);
        result.data = data;
        result.msg = msg;
        result.time = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        return result;
    }

    public static Result success(String msg) {
        Result result = new Result(true);
        result.msg = msg;
        result.time = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        return result;
    }

    public static Result fail(String msg) {
        Result result = new Result(false);
        result.msg = msg;
        result.time = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        return result;
    }

    public static Result fail(Object data, String msg) {
        Result result = new Result(false);
        result.data = data;
        result.msg = msg;
        result.time = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        return result;
    }
}
