package org.apache.zookeeper.test;

import org.apache.zookeeper.*;

/**
 * @author lixiaoyu
 * @since 2020/11/7
 */
public class TestMain {

    public static void main(String[] args) throws Exception {
        ZooKeeper zooKeeper = new ZooKeeper("127.0.0.1:2181", 1000, (event) -> {
            System.out.println("connect success");
        });
        zooKeeper.create("/test", "test".getBytes(), ZooDefs.Ids.OPEN_ACL_UNSAFE, CreateMode.PERSISTENT);
    }
}
