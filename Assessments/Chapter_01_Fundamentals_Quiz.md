# Chapter 01: Rust Fundamentals - Assessment Quiz

## Instructions
- Choose the best answer for each question
- Answers are provided at the end
- Passing score: 70% (14/20 correct)

---

## Section A: Ownership & Borrowing (5 questions)

### Q1. What happens when you assign a `String` to another variable?
```rust
let s1 = String::from("hello");
let s2 = s1;
println!("{}", s1);
```
- A) Compiles and prints "hello"
- B) Compile error - s1 has been moved
- C) Runtime error
- D) Creates a copy of the string

### Q2. Which statement about borrowing is correct?
- A) You can have multiple mutable references at once
- B) You can have one mutable reference OR multiple immutable references
- C) References always own their data
- D) Borrowing copies the data

### Q3. What is the output?
```rust
fn takes_ownership(s: String) {
    println!("{}", s);
}
let s = String::from("hello");
takes_ownership(s);
// Can we use s here?
```
- A) s is still valid
- B) s has been moved and is no longer valid
- C) s is automatically cloned
- D) Compile error at function definition

### Q4. How do you pass a string to a function without losing ownership?
- A) `fn process(s: String)`
- B) `fn process(s: &String)`
- C) `fn process(s: *String)`
- D) `fn process(s: Box<String>)`

### Q5. What does `&mut` mean?
- A) A constant reference
- B) A mutable reference allowing modification
- C) A copy of the data
- D) An owned pointer

---

## Section B: Error Handling (5 questions)

### Q6. Which type is used for recoverable errors?
- A) `Error<T>`
- B) `Option<T>`
- C) `Result<T, E>`
- D) `Panic<T>`

### Q7. What does the `?` operator do?
- A) Checks if a value is null
- B) Propagates errors to the calling function
- C) Converts Option to Result
- D) Unwraps or panics

### Q8. How do you handle a Result that might be an error?
```rust
let file = File::open("file.txt");
```
- A) `file.expect("Failed to open")`
- B) `file.unwrap()`
- C) `match file { Ok(f) => f, Err(e) => handle(e) }`
- D) All of the above

### Q9. What is the difference between `unwrap()` and `expect()`?
- A) No difference
- B) `expect()` allows a custom panic message
- C) `unwrap()` returns Option
- D) `expect()` doesn't panic

### Q10. When should you use `panic!`?
- A) For all errors
- B) When the error is unrecoverable or indicates a bug
- C) For network errors
- D) Never

---

## Section C: Structs & Enums (5 questions)

### Q11. How do you define a struct with named fields?
- A) `struct Point(i32, i32);`
- B) `struct Point { x: i32, y: i32 }`
- C) `struct Point = { x: i32, y: i32 }`
- D) `class Point { x: i32, y: i32 }`

### Q12. What is a tuple struct?
- A) A struct with named fields
- B) A struct with unnamed fields accessed by index
- C) A struct that implements Tuple
- D) A special type of array

### Q13. How do you implement methods on a struct?
- A) `fn Point::new() {}`
- B) `impl Point { fn new() -> Self {} }`
- C) `struct Point { fn new() {} }`
- D) `trait Point { fn new() {} }`

### Q14. What is the purpose of `#[derive(Debug)]`?
- A) Enables println!("{:?}", value)
- B) Enables serialization
- C) Enables copying
- D) Enables comparison

### Q15. What does `Option<T>` represent?
- A) An error or success
- B) A value that might be absent
- C) A boolean
- D) A reference

---

## Section D: Traits & Generics (5 questions)

### Q16. How do you define a generic function?
- A) `fn process<T>(item: T) {}`
- B) `fn process(item: <T>) {}`
- C) `fn<T> process(item: T) {}`
- D) `generic fn process(item: T) {}`

### Q17. What is a trait bound?
- A) A limit on trait size
- B) A constraint on what types can be used
- C) A trait with no methods
- D) An inherited trait

### Q18. How do you require a type to implement Clone?
- A) `fn process<T>(item: T) where T: Clone`
- B) `fn process<T: Clone>(item: T)`
- C) Both A and B
- D) `fn process(item: impl Clone)`

### Q19. What does `impl Trait` syntax do in return position?
- A) Returns a concrete type
- B) Returns any type implementing the trait
- C) Returns a reference
- D) Returns a Box

### Q20. How do you implement a trait for a struct?
```rust
trait Printable {
    fn print(&self);
}
struct Document { content: String }
```
- A) `impl Document: Printable { fn print(&self) {} }`
- B) `impl Printable for Document { fn print(&self) {} }`
- C) `struct Document implements Printable {}`
- D) `trait Document: Printable {}`

---

## Answer Key

<details>
<summary>Click to reveal answers</summary>

| Question | Answer | Explanation |
|----------|--------|-------------|
| Q1 | B | String is moved to s2, s1 is invalidated |
| Q2 | B | Rust's borrowing rules prevent data races |
| Q3 | B | Ownership is transferred to the function |
| Q4 | B | &String is an immutable reference (borrow) |
| Q5 | B | &mut creates a mutable reference |
| Q6 | C | Result<T, E> for recoverable errors |
| Q7 | B | ? propagates Err up the call stack |
| Q8 | D | All are valid ways to handle Result |
| Q9 | B | expect() provides custom panic message |
| Q10 | B | panic! for unrecoverable errors/bugs |
| Q11 | B | Named fields use curly braces |
| Q12 | B | Tuple structs have positional fields |
| Q13 | B | impl block defines methods |
| Q14 | A | Debug enables {:?} formatting |
| Q15 | B | Option represents optional values |
| Q16 | A | Generic type in angle brackets |
| Q17 | B | Constraints on generic types |
| Q18 | C | Both syntaxes are valid |
| Q19 | B | Returns opaque type implementing trait |
| Q20 | B | impl Trait for Type syntax |

**Passing Score: 14/20 (70%)**

</details>

---

## Scoring

- **18-20 correct**: Expert - Ready for advanced Rust
- **14-17 correct**: Proficient - Good foundation, proceed to next chapter
- **10-13 correct**: Developing - Review fundamentals
- **Below 10**: Needs improvement - Re-study Chapter 01

---

[← Back to Assessments](./README.md) | [Chapter 02 Quiz →](./Chapter_02_Skills_Quiz.md)
