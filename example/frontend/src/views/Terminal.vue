<template>
  <div class="container">


    <div class="termpage-window" id="terminal">

      <div fluid fill-height class="termpage-header" id="terminal_header"></div>

      <div class="termpage-body" id="terminal_body">
        <div id="terminal_output"></div>
        <p id="terminal_input_block" class="termpage-block termpage-input-block">
          <span id="terminal_prompt" class="termpage-prompt"></span>
          <input id="terminal_input" type="text" class="termpage-input"/>
        </p>
      </div>

      <div class="termpage-status" id="terminal_status"></div>
    </div>

  </div>
</template>

<script>
export default {
  name: 'Profile',
  computed: {
    currentUser() {
      console.log('Profile.currentUser', this.$store.state.auth.user)
      return this.$store.state.auth.user;
    }
  },
  mounted() {
    if (!this.currentUser) {
      this.$router.push('/login');
    }
  }
};
</script>


<style>

.termpage-window {
  display: grid;

  grid-template-columns: 100%;
  grid-template-rows: 30px auto 30px;
  grid-template-areas: "termpage-header" "termpage-body" "termpage-status";
  border: 1px solid #818;
  height: calc(100vh - 200px);
}

.termpage-body {
  background-color: #000;
  grid-area: termpage-body;
  overflow-y: auto;
}

.termpage-header {
  grid-area: termpage-header;
  background-color: blue;
}

.termpage-status {
  grid-area: termpage-status;
  background-color: blue;
}

.termpage-window a {
  background-color: #888;
  text-decoration: none;
  cursor: pointer;
}

.termpage-window a:hover {
  background-color: #333;
}

.termpage-window * {
  font-family: "Courier New", Courier, monospace;
  font-size: 16px;
  color: #ddd;
}

.termpage-header * {
  font-family: "Courier New", Courier, monospace;
  font-size: 16px;
  color: #ddd;
}

.termpage-status * {
  font-family: "Courier New", Courier, monospace;
  font-size: 16px;
  color: #ddd;
}

.termpage-input {
  background-color: black;
}

.termpage-input {
  background-color: #222;
  color: #ddd;
  caret-color: white;
}

.termpage-input-block {
  display: flex;
}

.termpage-input {
  border-width: 0;
  outline: 0;
  flex: 1;
  padding: 0;
}

.termpage-block,
.termpage-input {
  line-height: 20px;
}

.termpage-block {
  padding-left: 5px;
  padding-right: 5px;
}

.termpage-block {
  margin: 0;
  padding: 0;
}

pre.termpage-block {
  word-break: keep-all;
  white-space: pre-wrap !important;
}

.termpage-menu {
  background-color: #888;
}

.termpage-menu {
  display: flex;
  list-style: none;
  margin: 0;
  padding: 0;
}

.termpage-menu li:hover {
  background-color: #666;
  cursor: pointer;
}
</style>