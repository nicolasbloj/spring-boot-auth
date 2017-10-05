package com.auth0.samples.authapi.task;

import org.springframework.data.jpa.repository.JpaRepository;

public interface TaskRepository extends JpaRepository<Task, Long> {
}
// The persistence layer of our application is backed by an in-memory database called HSQLDB.
